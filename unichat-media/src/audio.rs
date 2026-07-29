//! Real microphone capture + speaker playback via cpal.
//!
//! Audio is mono 16-bit PCM at the device's sample rate, framed in ~20 ms
//! blocks. (Opus would compress this ~10x but its bindings need cmake, absent
//! on this toolchain; PCM is real, just higher-bandwidth — fine on LAN/onion.)
//! A lock-free ring buffer decouples cpal's real-time callback from the call's
//! send/receive threads.

use std::sync::{Arc, Mutex};

use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use cpal::SampleFormat;
use ringbuf::traits::{Consumer, Observer, Producer, Split};
use ringbuf::HeapRb;

/// Samples per 20 ms frame is `rate/50`; we key everything off the device rate.
pub struct AudioIo {
    pub sample_rate: u32,
    frame_samples: usize,
    // capture: cpal input pushes here; the send loop pops full frames.
    cap_cons: Arc<Mutex<ringbuf::HeapCons<i16>>>,
    // playback: the recv loop pushes here; cpal output pops.
    play_prod: Arc<Mutex<ringbuf::HeapProd<i16>>>,
    _in_stream: cpal::Stream,
    _out_stream: cpal::Stream,
}

// cpal::Stream isn't Send on all platforms; the streams live for the call's
// duration and are only dropped by the owning thread.
unsafe impl Send for AudioIo {}
// Streams are created and dropped by the owning thread; the ring buffers that
// the real-time callbacks touch are the only cross-thread state and are guarded
// by Mutex, so sharing an &AudioIo across the call's threads is sound.
unsafe impl Sync for AudioIo {}

impl AudioIo {
    /// Open the default input + output devices and start streaming.
    pub fn open() -> Result<Self, String> {
        let host = cpal::default_host();
        let input = host
            .default_input_device()
            .ok_or("no microphone (default input device)")?;
        let output = host
            .default_output_device()
            .ok_or("no speaker (default output device)")?;

        let in_cfg = input.default_input_config().map_err(|e| e.to_string())?;
        let sample_rate = in_cfg.sample_rate();
        let in_channels = in_cfg.channels() as usize;
        let frame_samples = (sample_rate as usize / 50).max(1); // 20 ms mono

        // Capture ring: input callback (producer) -> send loop (consumer).
        let cap_rb = HeapRb::<i16>::new(sample_rate as usize * 2); // ~1 s
        let (mut cap_prod, cap_cons) = cap_rb.split();
        // Playback ring: recv loop (producer) -> output callback (consumer).
        let play_rb = HeapRb::<i16>::new(sample_rate as usize * 2);
        let (play_prod, mut play_cons) = play_rb.split();

        // --- input stream: downmix to mono i16 and push ---
        let in_fmt = in_cfg.sample_format();
        let in_stream_cfg: cpal::StreamConfig = in_cfg.into();
        let build_in = |input: &cpal::Device| -> Result<cpal::Stream, String> {
            match in_fmt {
                SampleFormat::F32 => input.build_input_stream(
                    in_stream_cfg.clone(),
                    move |data: &[f32], _| {
                        for frame in data.chunks(in_channels) {
                            let s = frame.iter().copied().sum::<f32>() / in_channels as f32;
                            let v = (s.clamp(-1.0, 1.0) * i16::MAX as f32) as i16;
                            let _ = cap_prod.try_push(v);
                        }
                    },
                    |e| eprintln!("[audio] stream error: {e}"),
                    None,
                ),
                SampleFormat::I16 => input.build_input_stream(
                    in_stream_cfg.clone(),
                    move |data: &[i16], _| {
                        for frame in data.chunks(in_channels) {
                            let s = frame.iter().map(|&x| x as i32).sum::<i32>() / in_channels as i32;
                            let _ = cap_prod.try_push(s as i16);
                        }
                    },
                    |e| eprintln!("[audio] stream error: {e}"),
                    None,
                ),
                other => return Err(format!("unsupported input sample format {other:?}")),
            }
            .map_err(|e| e.to_string())
        };
        let in_stream = build_in(&input)?;

        // --- output stream: mono i16 -> device channels, silence on underrun ---
        let out_cfg = output.default_output_config().map_err(|e| e.to_string())?;
        let out_channels = out_cfg.channels() as usize;
        let out_fmt = out_cfg.sample_format();
        let out_stream_cfg: cpal::StreamConfig = out_cfg.into();
        let build_out = |output: &cpal::Device| -> Result<cpal::Stream, String> {
            match out_fmt {
                SampleFormat::F32 => output.build_output_stream(
                    out_stream_cfg.clone(),
                    move |data: &mut [f32], _| {
                        for frame in data.chunks_mut(out_channels) {
                            let v = play_cons.try_pop().unwrap_or(0);
                            let f = v as f32 / i16::MAX as f32;
                            for s in frame.iter_mut() {
                                *s = f;
                            }
                        }
                    },
                    |e| eprintln!("[audio] stream error: {e}"),
                    None,
                ),
                SampleFormat::I16 => output.build_output_stream(
                    out_stream_cfg.clone(),
                    move |data: &mut [i16], _| {
                        for frame in data.chunks_mut(out_channels) {
                            let v = play_cons.try_pop().unwrap_or(0);
                            for s in frame.iter_mut() {
                                *s = v;
                            }
                        }
                    },
                    |e| eprintln!("[audio] stream error: {e}"),
                    None,
                ),
                other => return Err(format!("unsupported output sample format {other:?}")),
            }
            .map_err(|e| e.to_string())
        };
        let out_stream = build_out(&output)?;

        in_stream.play().map_err(|e| e.to_string())?;
        out_stream.play().map_err(|e| e.to_string())?;

        Ok(Self {
            sample_rate,
            frame_samples,
            cap_cons: Arc::new(Mutex::new(cap_cons)),
            play_prod: Arc::new(Mutex::new(play_prod)),
            _in_stream: in_stream,
            _out_stream: out_stream,
        })
    }

    /// Pop one ~20 ms captured frame as little-endian i16 bytes, if available.
    pub fn next_capture_frame(&self) -> Option<Vec<u8>> {
        let mut cons = self.cap_cons.lock().unwrap();
        if cons.occupied_len() < self.frame_samples {
            return None;
        }
        let mut samples = vec![0i16; self.frame_samples];
        let n = cons.pop_slice(&mut samples);
        let mut bytes = Vec::with_capacity(n * 2);
        for s in &samples[..n] {
            bytes.extend_from_slice(&s.to_le_bytes());
        }
        Some(bytes)
    }

    /// Queue a received PCM frame (little-endian i16 bytes) for playback.
    pub fn play(&self, pcm: &[u8]) {
        let mut prod = self.play_prod.lock().unwrap();
        for chunk in pcm.chunks_exact(2) {
            let s = i16::from_le_bytes([chunk[0], chunk[1]]);
            let _ = prod.try_push(s);
        }
    }
}
