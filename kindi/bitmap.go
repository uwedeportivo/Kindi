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
	"image"
	"image/color"
	_ "image/jpeg"
	"image/png"
	"io"
)

func EncodePNG(w io.Writer, payload []byte, m image.Image) error {
	nrgba := newNRGBAImageLSBReaderWriter(m)

	err := writeLengthEncoded(nrgba, payload)
	if err != nil {
		return err
	}

	return png.Encode(w, nrgba.m)
}

func DecodePNG(rin io.Reader) ([]byte, error) {
	m, err := png.Decode(rin)
	if err != nil {
		return nil, err
	}

	nrgba := newNRGBAImageLSBReaderWriter(m)

	return readLengthEncoded(nrgba)
}

type nrgbaImageLSBReaderWriter struct {
	m       *image.NRGBA
	x, y, q int
}

func newNRGBAImageLSBReaderWriter(im image.Image) *nrgbaImageLSBReaderWriter {
	rv := new(nrgbaImageLSBReaderWriter)

	rv.x = 0
	rv.y = 0
	rv.q = -1

	b := im.Bounds()

	rv.m = image.NewNRGBA(image.Rect(0, 0, b.Max.X-b.Min.X, b.Max.Y-b.Min.Y))

	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			rv.m.Set(x-b.Min.X, y-b.Min.Y, im.At(x, y))
		}
	}
	return rv
}

func (it *nrgbaImageLSBReaderWriter) reset() {
	it.x = 0
	it.y = 0
	it.q = -1
}

func (it *nrgbaImageLSBReaderWriter) Read(p []byte) (n int, err error) {
	n = 0
	for j, _ := range p {
		var rv byte = 0
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
						return n, io.EOF
					}
				}
			}

			color := it.m.At(it.x, it.y).(color.NRGBA)
			var colorByte byte
			switch it.q {
			case 0:
				colorByte = color.R
			case 1:
				colorByte = color.G
			case 2:
				colorByte = color.B
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

func (it *nrgbaImageLSBReaderWriter) Write(p []byte) (n int, err error) {
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
						return n, io.EOF
					}
				}
			}

			color := it.m.At(it.x, it.y).(color.NRGBA)
			switch it.q {
			case 0:
				color.R = setLSB(color.R, (v>>i)&1)
			case 1:
				color.G = setLSB(color.G, (v>>i)&1)
			case 2:
				color.B = setLSB(color.B, (v>>i)&1)
			}
			it.m.Set(it.x, it.y, color)
		}
		n++
	}
	return n, nil
}
