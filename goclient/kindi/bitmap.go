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
	if !pi.bounds.Contains(image.Point{x, y}) {
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

