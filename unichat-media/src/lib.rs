//! unichat-media — real microphone/camera capture + playback for Umbra calls.
//!
//! Turns a connected media stream (from `unichat_core::call::rendezvous` over
//! the relay, then the PQ session handshake) into a **live full-duplex call**:
//! it captures the mic (and camera, for video), encrypts each frame with the
//! session-derived keys, and streams it; concurrently it receives, decrypts,
//! and plays audio / surfaces decoded video frames for display.
//!
//! Audio is PCM (Opus needs cmake, absent here); video is MJPEG (pure-Rust
//! JPEG). Both are real device I/O. Runtime behaviour (do you actually hear /
//! see) depends on the host's mic/camera/speaker and can only be validated on
//! a machine with those devices attached.

pub mod audio;
pub mod video;

use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use unichat_core::call::{media_key_pair, MediaFrame, MediaKind, MediaReceiver, MediaSender};

pub use video::VideoFrame;

const VIDEO_QUALITY: u8 = 60;
const VIDEO_INTERVAL: Duration = Duration::from_millis(66); // ~15 fps

/// A running call. Drop or call [`CallHandle::hang_up`] to end it.
pub struct CallHandle {
    stop: Arc<AtomicBool>,
    done: Arc<AtomicBool>,
    shutdown: TcpStream,
    threads: Vec<JoinHandle<()>>,
}

impl CallHandle {
    /// True once the peer hung up (or the media stream errored/closed).
    pub fn ended(&self) -> bool {
        self.done.load(Ordering::SeqCst)
    }

    /// End the call: signal all threads, close the socket, and join.
    pub fn hang_up(self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = self.shutdown.shutdown(std::net::Shutdown::Both);
        for t in self.threads {
            let _ = t.join();
        }
    }
}

/// Start a full-duplex call over `stream` (already handshaked). `is_caller` must
/// match the session's initiator role. `video` enables camera capture. If
/// `on_video` is set, decoded incoming video frames are delivered there (for a
/// GUI to display); voice-only callers pass `None`. `status` receives
/// human-readable progress/errors.
pub fn run_call(
    stream: TcpStream,
    call_secret: [u8; 32],
    is_caller: bool,
    video: bool,
    on_video: Option<Sender<VideoFrame>>,
    status: Arc<dyn Fn(String) + Send + Sync>,
) -> Result<CallHandle, String> {
    stream.set_nodelay(true).ok();
    let secret = Zeroizing::new(call_secret);
    let (send_key, recv_key) = media_key_pair(&secret, is_caller).map_err(|e| e.to_string())?;

    let write_half = stream.try_clone().map_err(|e| e.to_string())?;
    let read_half = stream.try_clone().map_err(|e| e.to_string())?;
    let shutdown = stream;

    let stop = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));
    let start = Instant::now();
    let mut threads: Vec<JoinHandle<()>> = Vec::new();

    // Audio device (best-effort; a call can proceed video-only if it fails).
    let audio = match audio::AudioIo::open() {
        Ok(a) => {
            status(format!("audio ready ({} Hz)", a.sample_rate));
            Some(Arc::new(a))
        }
        Err(e) => {
            status(format!("no audio: {e}"));
            None
        }
    };

    // One outbound queue drained by a single sender (shared seq counter).
    let (frame_tx, frame_rx) = std::sync::mpsc::channel::<(MediaKind, Vec<u8>)>();

    // --- sender thread ---
    {
        let mut sender = MediaSender::new(write_half, send_key);
        let stop = stop.clone();
        let status = status.clone();
        threads.push(std::thread::spawn(move || {
            let start = start;
            while !stop.load(Ordering::SeqCst) {
                match frame_rx.recv_timeout(Duration::from_millis(200)) {
                    Ok((kind, payload)) => {
                        let ts = start.elapsed().as_millis() as u32;
                        if sender.send(kind, ts, &payload).is_err() {
                            break;
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => break,
                }
            }
            let _ = &status;
        }));
    }

    // --- audio capture -> queue ---
    if let Some(audio) = &audio {
        let audio = audio.clone();
        let tx = frame_tx.clone();
        let stop = stop.clone();
        threads.push(std::thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                match audio.next_capture_frame() {
                    Some(pcm) => {
                        if tx.send((MediaKind::Audio, pcm)).is_err() {
                            break;
                        }
                    }
                    None => std::thread::sleep(Duration::from_millis(5)),
                }
            }
        }));
    }

    // --- video capture -> queue ---
    if video {
        let tx = frame_tx.clone();
        let stop = stop.clone();
        let status = status.clone();
        threads.push(std::thread::spawn(move || match video::Camera::open() {
            Ok(mut cam) => {
                status("camera ready".into());
                while !stop.load(Ordering::SeqCst) {
                    match cam.capture_jpeg(VIDEO_QUALITY) {
                        Ok(jpeg) => {
                            if tx.send((MediaKind::Video, jpeg)).is_err() {
                                break;
                            }
                        }
                        Err(e) => status(format!("camera: {e}")),
                    }
                    std::thread::sleep(VIDEO_INTERVAL);
                }
            }
            Err(e) => status(format!("no camera: {e}")),
        }));
    }
    drop(frame_tx); // only capture threads hold senders now

    // --- receiver thread: play audio / surface video ---
    {
        let mut receiver = MediaReceiver::new(read_half, recv_key);
        let audio = audio.clone();
        let stop = stop.clone();
        let done = done.clone();
        let status = status.clone();
        threads.push(std::thread::spawn(move || {
            loop {
                match receiver.recv() {
                    Ok(Some(MediaFrame { kind, payload, .. })) => match kind {
                        MediaKind::Audio => {
                            if let Some(a) = &audio {
                                a.play(&payload);
                            }
                        }
                        MediaKind::Video => {
                            if let Some(tx) = &on_video {
                                if let Some(vf) = video::decode_jpeg(&payload) {
                                    let _ = tx.send(vf);
                                }
                            }
                        }
                    },
                    Ok(None) | Err(_) => break,
                }
                if stop.load(Ordering::SeqCst) {
                    break;
                }
            }
            // Peer closed or the stream errored: wind the whole call down.
            stop.store(true, Ordering::SeqCst);
            done.store(true, Ordering::SeqCst);
            status("call ended".into());
        }));
    }

    status("call connected".into());
    Ok(CallHandle {
        stop,
        done,
        shutdown,
        threads,
    })
}
