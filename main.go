package main

import (
	"bufio"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/btcsuite/btcutil/base58"
	"github.com/jxskiss/base62"
	"github.com/martinlindhe/base36"
	"github.com/tilinna/z85"
	"github.com/u6du/go-rfc1924/base85"
	"toolman.org/encoding/base56"
)

type Flags struct {
	Encoding string
	Padding  bool
	Charset  string
	Binary   bool
	Version  bool
}

var flags = Flags{
	Encoding: "base32",
	Padding:  false,
}

type B56Slicer struct {
	Bytes []byte
}

func (s *B56Slicer) HasNext() bool {
	return len(s.Bytes) > 0
}

func (s *B56Slicer) Next() uint64 {
	if len(s.Bytes) == 0 {
		return 0
	}
	// fmt.Println(s.Bytes)
	var n uint64
	for i := 0; i < 8; i++ {
		if i < len(s.Bytes) {
			n = n<<8 | uint64(s.Bytes[i])
		} else {
			n = n << 8
		}
	}
	if len(s.Bytes) < 8 {
		s.Bytes = nil
	} else {
		s.Bytes = s.Bytes[8:]
	}
	return n
}

func NewB56Slicer(bytes []byte) *B56Slicer {
	return &B56Slicer{Bytes: bytes}
}

func B56Encode(enc *base56.Encoding, bytes []byte) string {
	slicer := NewB56Slicer(bytes)
	var result string
	for slicer.HasNext() {
		n := slicer.Next()
		result += enc.Encode(n)
	}
	return result
}

func B56Encode2(enc *base56.Encoding, bytes []byte, out io.Writer) {
	slicer := NewB56Slicer(bytes)
	for slicer.HasNext() {
		n := slicer.Next()
		out.Write([]byte(enc.Encode(n)))
	}
}

func init() {
	flag.Func("e", "encoding (base32,base36,base56,base58,base62,base64,base85,showcase)", func(s string) error {
		switch s {
		case "showcase":
			flags.Encoding = "showcase"
		case "base32", "b32":
			flags.Encoding = "base32"
		case "base36", "b36":
			flags.Encoding = "base36"
		case "base56", "b56":
			flags.Encoding = "base56"
		case "base58", "b58":
			flags.Encoding = "base58"
		case "base62", "b62":
			flags.Encoding = "base62"
		case "base64", "b64":
			flags.Encoding = "base64"
		case "base64url", "b64u", "b64url":
			flags.Encoding = "base64"
			flags.Charset = "url"
		case "base85", "ascii85", "b85", "a85":
			flags.Encoding = "base85"
		case "z85":
			flags.Encoding = "base85"
			flags.Charset = "z85"
		default:
			return fmt.Errorf("unsupported encoding: %s", s)
		}
		return nil
	})
	flag.Func("c", "charset (std,hex,url,alt,php,java,py3,z85)", func(s string) error {
		switch s {
		case "hex":
			flags.Charset = "hex"
		case "std":
			flags.Charset = "std"
		case "url":
			flags.Charset = "url"
		case "alt", "php", "java":
			flags.Charset = "alt"
		case "py3":
			flags.Charset = "py3"
		case "z85":
			flags.Charset = "z85"
		default:
			if len(s) != 32 {
				return fmt.Errorf("unsupported charset: %s", s)
			}
			flags.Charset = s
		}
		return nil
	})
	flag.BoolVar(&flags.Padding, "p", false, "enable padding")
	flag.BoolVar(&flags.Binary, "b", false, "binary input from stdin")
	flag.BoolVar(&flags.Version, "V", false, "show version")
}

var pat = regexp.MustCompile(`[^a-fA-F0-9]`)

func toHexCharsOnly(s string) string {
	tmp := pat.ReplaceAllString(s, "")
	if len(tmp)%2 == 1 {
		return "0" + tmp
	}
	return tmp
}

func shorten(params Params, src []byte, out io.Writer) (err error) {
	defer func() {
		p := recover()
		if p != nil {
			fmt.Println(p)
		}
	}()
	switch params.Encoding {
	case "base16":
		encoder := hex.NewEncoder(out)
		encoder.Write(src)
		return nil
	case "base32":
		var enc *base32.Encoding
		if params.Charset == "hex" {
			enc = base32.HexEncoding
		} else if len(flags.Charset) == 32 {
			enc = base32.NewEncoding(flags.Charset)
		} else {
			enc = base32.StdEncoding
		}
		if !flags.Padding {
			enc = enc.WithPadding(base32.NoPadding)
		}
		encoder := base32.NewEncoder(enc, out)
		defer encoder.Close()
		_, err = encoder.Write(src)
		return err
	case "base36":
		os.Stdout.Write(base36.EncodeBytesAsBytes(src))
		return nil
	case "base56":
		var enc *base56.Encoding
		if params.Charset == "alt" {
			enc = base56.Alt
		} else if flags.Charset == "py3" {
			enc = base56.Py3
		} else {
			enc = base56.Std
		}
		B56Encode2(enc, src, out)
		return nil
	case "base58":
		out.Write([]byte(base58.Encode(src)))
		return nil
	case "base62":
		out.Write(base62.Encode(src))
		return nil
	case "base64":
		var enc *base64.Encoding
		if params.Charset == "url" {
			if flags.Padding {
				enc = base64.URLEncoding
			} else {
				enc = base64.RawURLEncoding
			}
		} else {
			if flags.Padding {
				enc = base64.StdEncoding
			} else {
				enc = base64.RawStdEncoding
			}
		}
		encoder := base64.NewEncoder(enc, out)
		defer encoder.Close()
		encoder.Write(src)
		return nil
	case "base85":
		if params.Charset == "z85" {
			if len(src)%4 != 0 {
				src = append(src, make([]byte, 4-len(src)%4)...)
			}
			dstLen := z85.EncodedLen(len(src))
			dst := make([]byte, dstLen)
			_, err = z85.Encode(dst, src)
			if err != nil {
				return err
			}
			out.Write(dst)
		} else {
			encoder := base85.NewEncoder(out)
			defer encoder.Close()
			encoder.Write(src)
		}
		return nil
	}
	return fmt.Errorf("unsupported encoding: %s", params.Encoding)
}

type Params struct {
	Label    string
	Encoding string
	Charset  string
}

var showcaseEncodings = []Params{
	{"Hex(thru): ", "base16", ""},
	{"Base32:    ", "base32", ""},
	{"Base36:    ", "base36", ""},
	{"Base56:    ", "base56", ""},
	{"Base58:    ", "base58", ""},
	{"Base62:    ", "base62", ""},
	{"Base64:    ", "base64", ""},
	{"Base64url: ", "base64", "url"},
	{"Ascii85:   ", "base85", ""},
	{"Z85:       ", "base85", "z85"},
}

func shortenShowcase(src []byte, out io.Writer) (err error) {
	for _, params := range showcaseEncodings {
		fmt.Fprint(out, params.Label)
		err = shorten(params, src, out)
		fmt.Fprintln(out)
		if err != nil {
			return err
		}
	}
	return nil
}

func shortenHexEncoded(params Params, src string, out io.Writer) (err error) {
	bytes, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	shorten(params, bytes, out)
	return nil
}

func shortenHexEncodedShowcase(src string, out io.Writer) (err error) {
	bytes, err := hex.DecodeString(src)
	if err != nil {
		return err
	}
	return shortenShowcase(bytes, out)
}

func main() {
	flag.Parse()
	if flags.Version {
		fmt.Println("shorten/1.1.1")
		return
	}
	if flag.NArg() == 0 {
		if flags.Binary {
			bytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				fmt.Println(err)
				return
			}
			if flags.Encoding == "showcase" {
				err = shortenShowcase(bytes, os.Stdout)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			} else {
				err = shorten(Params{
					Encoding: flags.Encoding,
					Charset:  flags.Charset,
				}, bytes, os.Stdout)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}
		} else {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := scanner.Text()
				arg := toHexCharsOnly(line)
				if flags.Encoding == "showcase" {
					err := shortenHexEncodedShowcase(arg, os.Stdout)
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
					}
				} else {
					err := shortenHexEncoded(Params{
						Encoding: flags.Encoding,
						Charset:  flags.Charset,
					}, arg, os.Stdout)
					fmt.Fprintln(os.Stdout)
					if err != nil {
						fmt.Fprintln(os.Stderr, err)
					}
				}
			}
		}
	} else {
		for _, arg := range flag.Args() {
			arg = toHexCharsOnly(arg)
			if flags.Encoding == "showcase" {
				err := shortenHexEncodedShowcase(arg, os.Stdout)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			} else {
				err := shortenHexEncoded(Params{
					Encoding: flags.Encoding,
					Charset:  flags.Charset,
				}, arg, os.Stdout)
				fmt.Fprintln(os.Stdout)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
				}
			}
		}
	}
}
