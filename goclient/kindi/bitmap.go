// Copyright (c) 2011 Uwe Hoffmann. All rights reserved.

// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:

//    * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * The name Uwe Hoffmann may not be used to endorse or promote
// products derived from this software without specific prior written
// permission.

// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


package kindi

import (
	"fmt"
	"image"
	"image/png"
	"io"
	"math"
	"os"
)


type payloadImage struct {
	buf []byte
	bounds image.Rectangle
}

func newPayloadImage(payload []byte) *payloadImage {
	rv := new(payloadImage)

	rv.buf = payload
	
	numPixels := len(payload) >> 2 + 1

	width := int(math.Fmin(math.Sqrt(float64(numPixels)), 800.0))
	height := numPixels / width + 1

	rv.bounds = image.Rect(0, 0, width, height)
	return rv
}

func (pi *payloadImage) ColorModel() image.ColorModel {
	return image.NRGBAColorModel
}

func (pi *payloadImage) b(i int) byte {
	if i < len(pi.buf) {
		return pi.buf[i]
	} 
	return 0
}

func (pi *payloadImage) At(x, y int) image.Color {
	p := image.Point{x, y}

	if !p.In(pi.bounds) {
		return image.NRGBAColor{}
	}

	w := pi.bounds.Max.X
	pixel := y * w + x
	
	n := len(pi.buf)

	if pixel == 0 {
		return image.NRGBAColor{R:byte(n), G:byte(n >> 8), B:byte(n >> 16), A:byte(n >> 24)}
	}
	i := (pixel - 1) * 4
	return image.NRGBAColor{R:pi.b(i), G:pi.b(i + 1), B:pi.b(i + 2), A:pi.b(i + 3)}
}

func (pi *payloadImage) Bounds() image.Rectangle {
	return pi.bounds
}

func EncodePNG(w io.Writer, payload []byte) os.Error {
	return png.Encode(w, newPayloadImage(payload))
}

func DecodePNG(rin io.Reader) ([]byte, os.Error) {
	m, err := png.Decode(rin) 
	if err != nil {
		return nil, err
	}

	if m.ColorModel() != image.NRGBAColorModel {
		return nil, fmt.Errorf("Expected NRGBAColorModel, got %v instead", m.ColorModel())
	}

	r := m.Bounds()
	c := m.At(r.Min.X, r.Min.Y).(image.NRGBAColor)
		
	n := int(c.R) | int(c.G) << 8 | int(c.B) << 16 | int(c.A) << 24
	
	rv := make([]byte, n)	
	w := r.Max.X - r.Min.X

	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			if x == r.Min.X && y == r.Min.Y {
				continue
			}
			
			c = m.At(x, y).(image.NRGBAColor)
			pixel := y * w + x
			i := (pixel - 1) * 4

			if i < n {
				rv[i] = c.R
			} else {
				break
			}
			
			if i + 1 < n {
				rv[i + 1] = c.G
			} else {
				break
			}

			if i + 2 < n {
				rv[i + 2] = c.B
			} else {
				break
			}

			if i + 3 < n {
				rv[i + 3] = c.A
			} else {
				break
			}
		}
	}

	return rv, nil
}

