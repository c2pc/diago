// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: Copyright (c) 2024, Emir Aganovic

package sdp

import (
	"strconv"
	"strings"
)

const (
	FORMAT_VIDEO_TYPE_H264 = "96"
	FORMAT_VIDEO_TYPE_VP8  = "97"
	FORMAT_VIDEO_TYPE_VP9  = "98"
)

type VideoFormats []string

//	If the <proto> sub-field is "RTP/AVP" or "RTP/SAVP" the <fmt>//
//
// sub-fields contain RTP payload type numbers.
func (fmts VideoFormats) ToNumeric() (nfmts []int, err error) {
	nfmt := make([]int, len(fmts))
	for i, f := range fmts {
		nfmt[i], err = strconv.Atoi(f)
		if err != nil {
			return
		}
	}
	return nfmt, nil
}

func (fmts VideoFormats) String() string {
	out := make([]string, len(fmts))
	for i, v := range fmts {
		switch v {
		case FORMAT_VIDEO_TYPE_H264:
			out[i] = "96(H264)"
		case FORMAT_VIDEO_TYPE_VP8:
			out[i] = "97(VP8)"
		case FORMAT_VIDEO_TYPE_VP9:
			out[i] = "98(VP9)"
		default:
			// Unknown then just use as number
			out[i] = v
		}
	}
	return strings.Join(out, ",")
}
