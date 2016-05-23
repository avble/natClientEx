#!/bin/sh

export ROOTDIR="${PWD}"

./configure  --disable-sound  --disable-ssl --without-sip \
  --disable-resample     \
  --disable-sound        \
  --disable-oss          \
  --disable-video        \
  --disable-small-filter \
  --disable-large-filter \
  --disable-speex-aec    \
  --disable-g711-codec   \
  --disable-l16-codec    \
  --disable-gsm-codec    \
  --disable-g722-codec   \
  --disable-g7221-codec  \
  --disable-speex-codec  \
  --disable-ilbc-codec   \
  --disable-sdl          \
  --disable-ffmpeg       \
  --disable-v4l2         \
  --disable-openh264     \
  --disable-libyuv       \
  --disable-webrtc       \
  --disable-silk         \
  --disable-opus          
                          


