package main

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"flag"
	"fmt"
	"pkg.go.dev/golang.org/x/crypto/chacha20poly1305"
	"html"
	"io"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"time"
)

var cpuprofile = flag.String("cpuprofile", "", "write cpu profile `file`")
var nproc = flag.Int("c", 0, "Number of threads")
var duration = flag.Uint("t", 10, "Duration of each benchmark in seconds")
var run = flag.String("r", ".*", "Tests to run")

type benchInit func() func()

var (
	benchEscapeData = strings.Repeat("AAAAA < BBBBB > CCCCC & DDDDD ' EEEEE \" ", 10000)
	textTwain, _ = ioutil.ReadFile("./corp/mt.txt")
	textE, _ = ioutil.ReadFile("./corp/e.txt")
	easyRE          = "ABCDEFGHIJKLMNOPQRSTUVWXYZ$"
	easyREi         =  "(?i)ABCDEFGHIJklmnopqrstuvwxyz$"
        easyRE2         = "A[AB]B[BC]C[CD]D[DE]E[EF]F[FG]G[GH]H[HI]I[IJ]J$"
	mediumRE	=  "[XYZ]ABCDEFGHIJKLMNOPQRSTUVWXYZ$"
	hardRE		=  "[ -~]*ABCDEFGHIJKLMNOPQRSTUVWXYZ$"
	hardRE2		=  "ABCD|CDEF|EFGH|GHIJ|IJKL|KLMN|MNOP|OPQR|QRST|STUV|UVWX|WXYZ"
	text            []byte
)

func makeText(n int) []byte {
	if len(text) >= n {
		return text[:n]
	}
	text = make([]byte, n)
	x := ^uint32(0)
	for i := range text {
		x += x
		x ^= 1
		if int32(x) < 0 {
			x ^= 0x88888eef
		}
		if x%31 == 0 {
			text[i] = '\n'
		} else {
			text[i] = byte(x%(0x7E+1-0x20) + 0x20)
		}
	}
	return text
}

func BenchmarkMatch(re string) func() {
	r := regexp.MustCompile(re)
	size := 1 << 18
	t := makeText(size)

	return func() {
		if r.Match(t) {
			log.Fatalln("Match")
		}
	}
}

var goBenchmarks = []struct {
	name   string
	benc   func() func()
	report func(int) string
}{
	{"regexp.Match easy",
		func() func() {
			return BenchmarkMatch(easyRE)
		},
		func(total int) string { return fmt.Sprintf("%.2f ops/s", float64(total)/float64(*duration)) },
	},

	{"regexp.Match easy (i)",
		func() func() {
			return BenchmarkMatch(easyREi)
		},
		func(total int) string { return fmt.Sprintf("%.2f ops/s", float64(total)/float64(*duration)) },
	},

	{"regexp.Match easy2",
		func() func() {
			return BenchmarkMatch(easyRE2)
		},
		func(total int) string { return fmt.Sprintf("%.2f ops/s", float64(total)/float64(*duration)) },
	},

	{"regexp.Match medium",
		func() func() {
			return BenchmarkMatch(mediumRE)
		},
		func(total int) string { return fmt.Sprintf("%.2f ops/s", float64(total)/float64(*duration)) },
	},

	{"regexp.Match hard",
		func() func() {
			return BenchmarkMatch(hardRE)
		},
		func(total int) string { return fmt.Sprintf("%.2f ops/s", float64(total)/float64(*duration)) },
	},

	{"regexp.Match hard2",
		func() func() {
			return BenchmarkMatch(hardRE2)
		},
		func(total int) string { return fmt.Sprintf("%.2f ops/s", float64(total)/float64(*duration)) },
	},

	{"ECDSA-P256 Sign",
		func() func() {
			p256 := elliptic.P256()
			hashed := []byte("testing")
			priv, _ := ecdsa.GenerateKey(p256, rand.Reader)
			return func() { _, _, _ = ecdsa.Sign(rand.Reader, priv, hashed) }
		},
		func(total int) string { return fmt.Sprintf("%.2f ops/s", float64(total)/float64(*duration)) },
	},

	{"ECDSA-P256 Verify",
		func() func() {
			p256 := elliptic.P256()
			hashed := []byte("testing")
			priv, _ := ecdsa.GenerateKey(p256, rand.Reader)
			r, s, _ := ecdsa.Sign(rand.Reader, priv, hashed)
			return func() { ecdsa.Verify(&priv.PublicKey, hashed, r, s) }
		},
		func(total int) string { return fmt.Sprintf("%.2f ops/s", float64(total)/float64(*duration)) },
	},

	{"RSA2048 Sign",
		func() func() {
			test2048Key, _ := rsa.GenerateKey(rand.Reader, 2048)
			test2048Key.Precompute()
			hashed := sha256.Sum256([]byte("testing"))
			return func() { rsa.SignPKCS1v15(rand.Reader, test2048Key, crypto.SHA256, hashed[:]) }
		},
		func(total int) string { return fmt.Sprintf("%.2f ops/s", float64(total)/float64(*duration)) },
	},

	{"RSA2048 3-prime Sign",
		func() func() {
			test2048Key, _ := rsa.GenerateMultiPrimeKey(rand.Reader, 3, 2048)
			test2048Key.Precompute()
			hashed := sha256.Sum256([]byte("testing"))
			return func() { rsa.SignPKCS1v15(rand.Reader, test2048Key, crypto.SHA256, hashed[:]) }
		},
		func(total int) string { return fmt.Sprintf("%.2f ops/s", float64(total)/float64(*duration)) },
	},

	{"AES-128-GCM Enc",
		func() func() {
			buf := make([]byte, 8192)
			var key [16]byte
			var nonce [12]byte
			var ad [13]byte
			var out []byte
			aes, _ := aes.NewCipher(key[:])
			aesgcm, _ := cipher.NewGCM(aes)
			return func() { out = aesgcm.Seal(out[:0], nonce[:], buf, ad[:]) }
		},
		func(total int) string {
			return fmt.Sprintf("%.2f MiB/s", float64(total*8192)/float64(1024*1024)/float64(*duration))
		},
	},

	{"ChaCha20-Poly1305 Enc",
		func() func() {
			buf := make([]byte, 8192)
			var key [32]byte
			var nonce [12]byte
			var ad [13]byte
			var out []byte
			aead, _ := chacha20poly1305.New(key[:])
			return func() { out = aead.Seal(out[:0], nonce[:], buf, ad[:]) }
		},
		func(total int) string {
			return fmt.Sprintf("%.2f MiB/s", float64(total*8192)/float64(1024*1024)/float64(*duration))
		},
	},

	{"html.EscapeString",
		func() func() {
			n := 0
			return func() { n += len(html.EscapeString(benchEscapeData)) }
		},
		func(total int) string {
			return fmt.Sprintf("%.2f MiB/s", float64(len(benchEscapeData)*total)/float64(1024*1024)/float64(*duration))
		},
	},

	{"html.UnescapeString",
		func() func() {
			n := 0
			e := html.EscapeString(benchEscapeData)
			return func() { n += len(html.UnescapeString(e)) }
		},
		func(total int) string {
			return fmt.Sprintf("%.2f MiB/s", float64(len(html.EscapeString(benchEscapeData))*total)/float64(1024*1024)/float64(*duration))
		},
	},

	{"compress/gzip compression Twain, -8",
		func() func() {
			var b bytes.Buffer
			w, _ := gzip.NewWriterLevel(&b, 8)

			return func() {
				b.Reset()
				w.Reset(&b)
				w.Write(textTwain)
				w.Flush()
				w.Close()
			}
		},
		func(total int) string {
			return fmt.Sprintf("%.2f MiB/s", float64(total*len(textTwain))/float64(1024*1024)/float64(*duration))
		},
	},

	{"compress/gzip decompression Twain, -d",
		func() func() {
			var b bytes.Buffer
			w, _ := gzip.NewWriterLevel(&b, 8)
			w.Write(textTwain)
			w.Flush()
			w.Close()

			return func() {
				r, _ := gzip.NewReader(bytes.NewReader(b.Bytes()))
				io.Copy(ioutil.Discard, r)
			}
		},
		func(total int) string {
			return fmt.Sprintf("%.2f MiB/s", float64(total*len(textTwain))/float64(1024*1024)/float64(*duration))
		},
	},

	{"compress/gzip compression digits, -8",
		func() func() {
			var b bytes.Buffer
			w, _ := gzip.NewWriterLevel(&b, 8)

			return func() {
				b.Reset()
				w.Reset(&b)
				w.Write(textE)
				w.Flush()
				w.Close()
			}
		},
		func(total int) string {
			return fmt.Sprintf("%.2f MiB/s", float64(total*len(textE))/float64(1024*1024)/float64(*duration))
		},
	},

	{"compress/gzip decompression digits",
		func() func() {
			var b bytes.Buffer
			w, _ := gzip.NewWriterLevel(&b, 8)
			w.Write(textE)
			w.Flush()
			w.Close()

			return func() {
				r, _ := gzip.NewReader(bytes.NewReader(b.Bytes()))
				io.Copy(ioutil.Discard, r)
			}
		},
		func(total int) string {
			return fmt.Sprintf("%.2f MiB/s", float64(total*len(textE))/float64(1024*1024)/float64(*duration))
		},
	},
}



func bench(init benchInit, nThreads int) int {
	var wg sync.WaitGroup
	start := time.Now()
	sum := make(chan int, nThreads)

	wg.Add(nThreads)

	for i := 0; i < nThreads; i++ {
		go func() {
			b := init()
			total := 0

			for time.Now().Sub(start) < time.Duration(*duration)*time.Second {
				b()
				total += 1
			}

			sum <- total
			wg.Done()
		}()
	}

	wg.Wait()
	close(sum)

	total := 0
	for t := range sum {
		total += t
	}

	return total
}

func main() {
	flag.Parse()

	if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal("could not create CPU profile: ", err)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			log.Fatal("could not start CPU profile: ", err)
		}
		defer pprof.StopCPUProfile()
	}

	if *nproc < 0 {
		*nproc = 0
	}

	if *nproc != 0 {
		runtime.GOMAXPROCS(*nproc)
	} else {
		*nproc = runtime.GOMAXPROCS(0)
	}

	log.Println("Max threads:", *nproc, "; CPUs available:", runtime.NumCPU())

	match := regexp.MustCompile(*run)

	for _, b := range goBenchmarks {

		if !match.MatchString(b.name) {
			continue
		}

		totalSingle := bench(b.benc, 1)
		totalMulti := bench(b.benc, *nproc)
		fmt.Printf("%s,%s,%s\n", b.name, b.report(totalSingle), b.report(totalMulti))
	}
}
