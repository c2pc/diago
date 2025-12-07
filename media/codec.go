// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2024, Emir Aganovic

package media

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/c2pc/diago/media/sdp"
)

var (
	// Here are some codec constants that can be reused
	CodecAudioUlaw          = Codec{PayloadType: 0, SampleRate: 8000, SampleDur: 20 * time.Millisecond, NumChannels: 1, Name: "PCMU"}
	CodecAudioAlaw          = Codec{PayloadType: 8, SampleRate: 8000, SampleDur: 20 * time.Millisecond, NumChannels: 1, Name: "PCMA"}
	CodecAudioOpus          = Codec{PayloadType: 96, SampleRate: 48000, SampleDur: 20 * time.Millisecond, NumChannels: 2, Name: "opus"}
	CodecTelephoneEvent8000 = Codec{PayloadType: 101, SampleRate: 8000, SampleDur: 20 * time.Millisecond, NumChannels: 1, Name: "telephone-event"}

	// Video codecs
	// H.264 is the most common video codec for SIP
	CodecVideoH264 = Codec{PayloadType: 96, SampleRate: 90000, SampleDur: 33 * time.Millisecond, NumChannels: 1, Name: "H264"}
	// VP8 is commonly used in WebRTC
	CodecVideoVP8 = Codec{PayloadType: 97, SampleRate: 90000, SampleDur: 33 * time.Millisecond, NumChannels: 1, Name: "VP8"}
	// VP9 is a newer codec
	CodecVideoVP9 = Codec{PayloadType: 98, SampleRate: 90000, SampleDur: 33 * time.Millisecond, NumChannels: 1, Name: "VP9"}
)

type Codec struct {
	Name        string
	PayloadType uint8
	SampleRate  uint32
	SampleDur   time.Duration
	NumChannels int // 1 or 2
}

func (c *Codec) String() string {
	return fmt.Sprintf("name=%s pt=%d rate=%d dur=%s channels=%d", c.Name, c.PayloadType, c.SampleRate, c.SampleDur.String(), c.NumChannels)
}

// SampleTimestamp returns number of samples as RTP Timestamp measure
func (c *Codec) SampleTimestamp() uint32 {
	return uint32(float64(c.SampleRate) * c.SampleDur.Seconds())
}

// Samples16 returns PCM 16 bit samples size
func (c *Codec) Samples16() int {
	return c.SamplesPCM(16)
}

// Samples is samples in pcm
func (c *Codec) SamplesPCM(bitSize int) int {
	return bitSize / 8 * int(float64(c.SampleRate)*c.SampleDur.Seconds()) * c.NumChannels
}

func CodecAudioFromSession(s *MediaSession) Codec {
	codec, exists := CodecAudioFromList(s.filterCodecs)
	if !exists {
		return s.Codecs[0]
	}

	return codec
}

// CodecFromSession returns the first codec from the session, whether audio or video
// It prefers filterCodecs (negotiated codecs) over Codecs
func CodecFromSession(s *MediaSession) Codec {
	if len(s.filterCodecs) > 0 {
		return s.filterCodecs[0]
	}
	if len(s.Codecs) > 0 {
		return s.Codecs[0]
	}
	// Fallback to default audio codec if no codecs available
	return CodecAudioUlaw
}

func CodecAudioFromList(codecs []Codec) (Codec, bool) {
	for _, codec := range codecs {
		if codec.Name == "telephone-event" {
			continue
		}
		// Skip video codecs
		if codec.Name == "H264" || codec.Name == "VP8" || codec.Name == "VP9" {
			continue
		}

		return codec, true
	}

	return Codec{}, false
}

// Deprecated: Use CodecAudioFromPayloadType
func CodecFromPayloadType(payloadType uint8) Codec {
	f := strconv.Itoa(int(payloadType))
	return mapSupportedCodec(f)
}

func CodecAudioFromPayloadType(payloadType uint8) (Codec, error) {
	f := strconv.Itoa(int(payloadType))
	switch f {
	case sdp.FORMAT_TYPE_ALAW:
		return CodecAudioAlaw, nil
	case sdp.FORMAT_TYPE_ULAW:
		return CodecAudioUlaw, nil
	case sdp.FORMAT_TYPE_OPUS:
		return CodecAudioOpus, nil
	case sdp.FORMAT_TYPE_TELEPHONE_EVENT:
		return CodecTelephoneEvent8000, nil
	}
	return Codec{}, fmt.Errorf("non supported audio codec: %d", payloadType)
}

func mapSupportedCodec(f string) Codec {
	// TODO: Here we need to be more explicit like matching sample rate, channels and other

	switch f {
	case sdp.FORMAT_TYPE_ALAW:
		return CodecAudioAlaw
	case sdp.FORMAT_TYPE_ULAW:
		return CodecAudioUlaw
	case sdp.FORMAT_TYPE_OPUS:
		return CodecAudioOpus
	case sdp.FORMAT_TYPE_TELEPHONE_EVENT:
		return CodecTelephoneEvent8000
	default:
		// Note: Video codecs (H264, VP8, VP9) use dynamic payload types (96-127)
		// which can overlap with audio codecs like Opus (96). We can't determine
		// the codec type from format string alone - it should be parsed from SDP rtpmap.
		// This function is a fallback and will use default parameters based on PayloadType range.
		// Try to parse as numeric payload type
		pt, err := sdp.FormatNumeric(f)
		if err != nil {
			slog.Warn("Format is non numeric value", "format", f)
			// Return default audio codec if parsing fails
			return CodecAudioUlaw
		}

		// Check if it's in the dynamic payload type range (96-127)
		// This range is commonly used for video codecs, but can also be used for audio
		// Without rtpmap, we can't determine the exact codec, so we'll use default parameters
		// This function should ideally not be used for dynamic payload types - they should be parsed from SDP
		if pt >= 96 && pt <= 127 {
			// Dynamic payload type range - could be video or audio
			// Default to video codec with 90000 Hz (common for video)
			// Note: This is a fallback - proper codec info should come from SDP rtpmap
			return Codec{
				PayloadType: pt,
				SampleRate:  90000,                 // Common video clock rate
				SampleDur:   33 * time.Millisecond, // Common video frame duration
				NumChannels: 1,
			}
		}

		// Default to audio codec (8000 Hz) for static payload types
		slog.Warn("Unsupported format. Using default clock rate", "format", f)
		return Codec{
			PayloadType: pt,
			SampleRate:  8000,
			SampleDur:   20 * time.Millisecond,
		}
	}
}

// func CodecsFromSDP(log *slog.Logger, sd sdp.SessionDescription, codecsAudio []Codec) error {
// 	md, err := sd.MediaDescription("audio")
// 	if err != nil {
// 		return err
// 	}

// 	codecs := make([]Codec, len(md.Formats))
// 	attrs := sd.Values("a")
// 	n, err := CodecsFromSDPRead(log, md, attrs, codecs)
// 	if err != nil {
// 		return err
// 	}
// 	codecs = codecs[:n]
// }

// CodecsFromSDP will try to parse as much as possible, but it will return also error in case
// some properties could not be read
// You can take what is parsed or return error
func CodecsFromSDPRead(formats []string, attrs []string, codecsAudio []Codec) (int, error) {
	n := 0
	var rerr error
	for _, f := range formats {
		if f == "0" {
			codecsAudio[n] = CodecAudioUlaw
			n++
			continue
		}

		if f == "8" {
			codecsAudio[n] = CodecAudioAlaw
			n++
			continue
		}

		pt64, err := strconv.ParseUint(f, 10, 8)
		if err != nil {
			rerr = errors.Join(rerr, fmt.Errorf("format type failed to conv to integer, skipping f=%s: %w", f, err))
			continue
		}
		pt := uint8(pt64)

		for _, a := range attrs {
			// a=rtpmap:<payload type> <encoding name>/<clock rate> [/<encoding parameters>]
			pref := "rtpmap:" + f + " "
			if strings.HasPrefix(a, pref) {
				// Check properties of this codec
				str := a[len(pref):]
				// TODO use more efficient reading props
				props := strings.Split(str, " ")
				firstProp := props[0]
				propsCodec := strings.Split(firstProp, "/")
				if len(propsCodec) < 2 {
					rerr = errors.Join(rerr, fmt.Errorf("bad rtmap property a=%s", a))
					continue
				}

				encodingName := propsCodec[0]
				sampleRateStr := propsCodec[1]
				sampleRate64, err := strconv.ParseUint(sampleRateStr, 10, 32)
				if err != nil {
					rerr = errors.Join(rerr, fmt.Errorf("sample rate failed to parse a=%s: %w", a, err))
					continue
				}

				// Determine SampleDur based on codec type
				// Video codecs typically use 33ms frame duration
				// Audio codecs typically use 20ms packet duration
				sampleDur := 20 * time.Millisecond
				if encodingName == "H264" || encodingName == "VP8" || encodingName == "VP9" {
					sampleDur = 33 * time.Millisecond
				}

				codec := Codec{
					Name:        encodingName,
					PayloadType: pt,
					SampleRate:  uint32(sampleRate64),
					SampleDur:   sampleDur,
					NumChannels: 1,
				}

				if len(propsCodec) == 3 {
					numChannels, err := strconv.ParseUint(propsCodec[2], 10, 32)
					if err == nil {
						codec.NumChannels = int(numChannels)
					}
				}
				// Проверяем границы массива перед записью
				if n >= len(codecsAudio) {
					rerr = errors.Join(rerr, fmt.Errorf("codecs array overflow: tried to write at index %d but array size is %d", n, len(codecsAudio)))
					break // Прерываем внутренний цикл по attrs
				}
				codecsAudio[n] = codec
				n++
				break // Прерываем цикл по attrs после первого совпадения для этого формата
			}
		}
	}
	return n, rerr
}
