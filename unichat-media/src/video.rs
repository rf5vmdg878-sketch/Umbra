//! Real camera capture + JPEG (MJPEG-style) encode/decode.
//!
//! Each video frame is captured from the default camera as RGB, JPEG-encoded
//! (pure-Rust `jpeg-encoder`, no C codec needed), sent over the encrypted media
//! channel, and decoded on the far side (`image`) to RGBA for display.

use jpeg_encoder::{ColorType, Encoder};
use nokhwa::pixel_format::RgbFormat;
use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
use nokhwa::Camera as NkCamera;

/// A decoded video frame ready to upload as a texture.
pub struct VideoFrame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

pub struct Camera {
    inner: NkCamera,
}

impl Camera {
    /// Open the default camera (index 0) and start streaming.
    pub fn open() -> Result<Self, String> {
        let format = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
        let mut inner = NkCamera::new(CameraIndex::Index(0), format).map_err(|e| e.to_string())?;
        inner.open_stream().map_err(|e| e.to_string())?;
        Ok(Self { inner })
    }

    /// Capture one frame and JPEG-encode it.
    pub fn capture_jpeg(&mut self, quality: u8) -> Result<Vec<u8>, String> {
        let frame = self.inner.frame().map_err(|e| e.to_string())?;
        let rgb = frame
            .decode_image::<RgbFormat>()
            .map_err(|e| e.to_string())?;
        let (w, h) = (rgb.width(), rgb.height());
        let mut out = Vec::new();
        Encoder::new(&mut out, quality)
            .encode(rgb.as_raw(), w as u16, h as u16, ColorType::Rgb)
            .map_err(|e| e.to_string())?;
        Ok(out)
    }
}

/// Decode a received JPEG frame to RGBA for display. Returns `None` on garbage.
pub fn decode_jpeg(bytes: &[u8]) -> Option<VideoFrame> {
    // Bound decoded dimensions so a small-but-huge-dimensioned JPEG can't force a
    // multi-GB RGBA allocation (decompression bomb) from an authenticated-but-
    // hostile peer. MAX_MEDIA_FRAME only caps the *compressed* size.
    let mut reader =
        image::ImageReader::with_format(std::io::Cursor::new(bytes), image::ImageFormat::Jpeg);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(7680); // 8K ceiling
    limits.max_image_height = Some(4320);
    reader.limits(limits);
    let rgba = reader.decode().ok()?.to_rgba8();
    let (width, height) = (rgba.width(), rgba.height());
    Some(VideoFrame {
        width,
        height,
        rgba: rgba.into_raw(),
    })
}
