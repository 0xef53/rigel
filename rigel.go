package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

const (
	READER_BLOCKSIZE = 512 * 1024      // 512K
	MAXFILESIZE      = 2 * 1024 * 1024 // 2M
)

type Database struct {
	Signatures []Signature `xml:"signature"`
}

type Signature struct {
	Id        int    `xml:"id,attr"`
	Title     string `xml:"title,attr"`
	Type      string `xml:"sever,attr"`
	Signature string `xml:",chardata"`
	Regexp    *regexp.Regexp
}

type FileExtensions map[string]struct{}

func (li FileExtensions) String() string {
	return fmt.Sprint(len(li))
}

func (li *FileExtensions) Set(value string) error {
	if len(*li) > 0 {
		return fmt.Errorf("flag already set")
	}
	for _, s := range strings.Split(value, ",") {
		s = strings.TrimSpace(s)
		if len(s) == 0 {
			continue
		}
		if s[0] == '.' {
			(*li)[s] = struct{}{}
		} else {
			(*li)[fmt.Sprintf(".%s", s)] = struct{}{}
		}
	}
	return nil
}

var (
	DBFILE   = "malware_db.xml"
	ROOTDIR  = "."
	MAXPROCS = 1
	FFILTER  = make(FileExtensions)
	SKIPSOFT = false
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	flag.StringVar(&DBFILE, "database", DBFILE, "manul malware xml database `file` (can be http link)")
	flag.StringVar(&ROOTDIR, "rootdir", ROOTDIR, "filesystem `directory` to scan recursively")
	flag.IntVar(&MAXPROCS, "n", MAXPROCS, "number of files to check concurrently")
	flag.Var(&FFILTER, "filter", "comma-separated list of file `extensions` to scan (default: all text files)")
	flag.BoolVar(&SKIPSOFT, "skip-soft", SKIPSOFT, "skip soft signatures")
	flag.Parse()

	if MAXPROCS < 1 {
		MAXPROCS = 1
	}

	normalizers, err := compileNormalizers()
	if err != nil {
		log.Fatalln("[fatal] failed to compile normalizers:", err)
	}

	db, err := readDatabase(DBFILE)
	if err != nil {
		log.Fatalln("[fatal] database error:", err)
	}

	cPaths := walk(ROOTDIR)

	// Starting scanner-workers
	var wg sync.WaitGroup
	for i := 0; i < MAXPROCS; i++ {
		wg.Add(1)
		go worker(db.Signatures, normalizers, cPaths, &wg)
	}
	wg.Wait()
}

func worker(sigs []Signature, nr []*regexp.Regexp, cPaths chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	for p := range cPaths {
		checkFile(p, sigs, nr)
	}
}

func unquoteStr(s []byte) []byte {
	u, err := strconv.Unquote("'" + string(s) + "'")
	if err != nil {
		return []byte{}
	}
	return []byte(u)
}

func checkFile(path string, signatures []Signature, nr []*regexp.Regexp) {
	f, err := os.Open(path)
	if err != nil {
		log.Printf("[warning] %s: %s\n", err, path)
		return
	}
	defer f.Close()


	if len(FFILTER) == 0 {
		head := make([]byte, 512)
		if n, err := f.Read(head); err == nil {
			mimeType := http.DetectContentType(head[:n])
			switch {
			case strings.HasPrefix(mimeType, "text/"):
			case strings.HasSuffix(mimeType, "/xml"):
			default:
				return
			}
		}
		if _, err := f.Seek(0, os.SEEK_SET); err != nil {
			log.Printf("[warning] %s: %s\n", err, path)
			return
		}
	}

	st, err := f.Stat()
	if err != nil {
		log.Printf("[warning] %s: %s\n", err, path)
		return
	}
	if st.Size() > MAXFILESIZE {
		log.Printf("[warning] file size more than %dM: %s\n", MAXFILESIZE>>(10*2), path)
		return
	}

	c, err := ioutil.ReadAll(f)
	if err != nil {
		log.Printf("[warning] %s: %s\n", err, path)
		return
	}
	// Normalize content
	for _, r := range nr[:2] {
		c = r.ReplaceAll(c, []byte{})
	}
	for _, r := range nr[2:] {
		c = r.ReplaceAllFunc(c, unquoteStr)
	}

	for _, s := range signatures {
		if s.Regexp.Match(c) {
			fmt.Printf("Matched: %s (signature id = %d): %s\n", s.Title, s.Id, path)
			return
		}
	}
}

func compileNormalizers() ([]*regexp.Regexp, error) {
	exprs := []string{
		`(?si:[\'"]\s*?\.\s*?[\'"])`,
		`(?si:/\*.*?\*/)`,
		`(?i:\\x([a-fA-F0-9]{1,2}))`,
		`\\([0-9]{1,3})`,
	}

	compiled := make([]*regexp.Regexp, 0, len(exprs))

	for _, i := range exprs {
		r, err := regexp.Compile(i)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, r)
	}
	return compiled, nil
}

func readDatabase(path string) (*Database, error) {
	db := Database{}

	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		resp, err := http.Get(DBFILE)
		if err != nil {
			return nil, fmt.Errorf("cannot fetch database file (%s): %s", DBFILE, err)
		}
		defer resp.Body.Close()
		if err := xml.NewDecoder(resp.Body).Decode(&db); err != nil {
			return nil, err
		}
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()

		if err := xml.NewDecoder(f).Decode(&db); err != nil {
			return nil, err
		}
	}

	if len(db.Signatures) == 0 {
		return nil, fmt.Errorf("no signatures loaded, check file format")
	}

	for i, sig := range db.Signatures {
		r, err := regexp.Compile(sig.Signature)
		if err != nil {
			return nil, fmt.Errorf("failed to compile signature %d regexp %q: %v", sig.Id, sig.Signature, err)
		}
		db.Signatures[i].Regexp = r
	}

	if SKIPSOFT {
		var count int
		for _, sig := range db.Signatures {
			if sig.Type == "c" {
				count++
			}
		}
		critSignatures := make([]Signature, 0, count)
		for _, sig := range db.Signatures {
			if sig.Type == "c" {
				critSignatures = append(critSignatures, sig)
			}
		}
		return &Database{critSignatures}, nil
	}

	return &db, nil
}

func walk(rootdir string) chan string {
	cPaths := make(chan string, 10)

	walkFn := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Println("[fatal] walk error:", err)
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if _, ok := FFILTER[filepath.Ext(path)]; !ok && len(FFILTER) > 0 {
			return nil
		}
		cPaths <- path
		return nil
	}

	go func() {
		defer close(cPaths)
		if err := filepath.Walk(rootdir, walkFn); err != nil {
			log.Println("[fatal] walk error:", err)
		}
	}()

	return cPaths
}
