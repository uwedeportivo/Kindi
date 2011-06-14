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

type nrgbaImageLSBReaderWriter struct {
	m *image.NRGBA
	x, y, q int
}

func newNRGBAImageLSBReaderWriter(im image.Image) *nrgbaImageLSBReaderWriter {
	rv := new(nrgbaImageLSBReaderWriter)

	rv.x = 0
	rv.y = 0
	rv.q = -1

	b := im.Bounds()

	rv.m = image.NewNRGBA(b.Max.X - b.Min.X, b.Max.Y - b.Min.Y)

	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			rv.m.Set(x - b.Min.X, y - b.Min.Y, im.At(x, y))
		}
	}
	return rv
}

func (it *nrgbaImageLSBReaderWriter) reset() {
	it.x = 0
	it.y = 0
	it.q = -1
}

func (it *nrgbaImageLSBReaderWriter) Read(p []byte) (n int, err os.Error) {
	n = 0
	for j, _ := range p {
		var rv byte = 0
		var i uint8
		for  i = 0; i < 8; i++ {
			it.q++
			if it.q == 3 {
				it.q = 0
				it.x++
				if it.x == it.m.Rect.Max.X {
					it.x = it.m.Rect.Min.X
					it.y++
					if it.y == it.m.Rect.Max.Y {
						return n, os.EOF
					}
				}
			}
			
			color := it.m.At(it.x, it.y).(image.NRGBAColor)
			var colorByte byte
			switch (it.q) {
			case 0 : colorByte = color.R
			case 1 : colorByte = color.G
			case 2 : colorByte = color.B
			}
			rv = rv | ((colorByte & 1) << i)
		}
		p[j] = rv
		n++
	}
	return n, nil
}

func setLSB(val, bit byte) byte {
	var rv byte
	if bit == 1 {
		rv = val | 1
	} else {
		rv = val & 0xfe
	}
	return rv
}

func (it *nrgbaImageLSBReaderWriter) Write(p []byte) (n int, err os.Error) {
	n = 0
	for _, v := range p {
		var i uint8
		for i = 0; i < 8; i++ {
			it.q++
			if it.q == 3 {
				it.q = 0
				it.x++
				if it.x == it.m.Rect.Max.X {
					it.x = it.m.Rect.Min.X
					it.y++
					if it.y == it.m.Rect.Max.Y {
						return n, os.EOF
					}
				}
                       }
			
			color := it.m.At(it.x, it.y).(image.NRGBAColor)
			switch (it.q) {
			case 0 : color.R = setLSB(color.R, (v >> i) & 1)
			case 1 : color.G = setLSB(color.G, (v >> i) & 1)
			case 2 : color.B = setLSB(color.B, (v >> i) & 1)
			}
			it.m.Set(it.x, it.y, color)
		}
		n++
	}
	return n, nil
}

