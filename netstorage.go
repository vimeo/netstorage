package netstorage

import (
	"code.google.com/p/go.text/encoding/charmap"
	"code.google.com/p/go.text/transform"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"time"
)

const version = "1"

type httpError struct {
	error
	code int
}

func NewHTTPError(resp *http.Response) *httpError {
	code := resp.StatusCode
	return &httpError{
		error: errors.New(http.StatusText(code)),
		code:  code,
	}
}

// Api instances are safe for concurrent use by multiple goroutines
type Api struct {
	client  *http.Client
	KeyName string
	Secret  string
}

func NewApi(keyName, secret string) Api {
	// default Seed would probably be fine, random ints don't need to be hard to crack,
	// just different enough. but let's keep it like this to be sure.
	rand.Seed(time.Now().UTC().UnixNano())
	client := &http.Client{}
	return Api{client, keyName, secret}
}

func (api Api) auth(req *http.Request, rel_path, action string) {
	data, signature := api.sign(rel_path, action, -1, -1)
	req.Header.Add("X-Akamai-ACS-Auth-Data", data)
	req.Header.Add("X-Akamai-ACS-Auth-Sign", signature)
}
func (api Api) sign(rel_path, action string, id, timestamp int) (data, signature string) {
	// these cases will mostly be true.  but for testing,
	// it can be useful to provide them explicitly
	if id < 0 {
		id = rand.Int()
	}
	if timestamp < 0 {
		timestamp = int(time.Now().Unix())
	}
	data = fmt.Sprintf("5, 0.0.0.0, 0.0.0.0, %d, %d, %s", timestamp, id, api.KeyName)
	sign_string := rel_path + "\n" + "x-akamai-acs-action:" + action + "\n"
	mac := hmac.New(sha256.New, []byte(api.Secret))
	mac.Write([]byte(data + sign_string))
	signature = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return
}

type AkFile struct {
	Type  string `xml:"type,attr"`
	Name  string `xml:"name,attr"`
	Size  int    `xml:"size,attr"`
	Md5   string `xml:"md5,attr"`
	Mtime uint32 `xml:"mtime,attr"`
}
type Resume struct {
	Start string `xml:"start,attr"`
}
type ListResponse struct {
	File   []AkFile `xml:"file"`
	Resume Resume   `xml:"resume"`
}

// path: begin response output with noted subdirectory
// resume: resume from this point (takes precedence over path)
func (api Api) List(cpcode uint, storage_group, path, resume string, limit uint) (listResp ListResponse, err error) {
	host := storage_group + "-nsu.akamaihd.net"
	action := fmt.Sprintf("version=%s&action=list&format=xml&max_entries=%d", version, limit)
	var rel_path string
	if resume != "" {
		rel_path = resume
	} else {
		if strings.HasPrefix(path, "/") {
			path = path[1:]
		}
		rel_path = fmt.Sprintf("/%d/%s", cpcode, path)
	}
	abs_path := "http://" + host + rel_path
	req, err := http.NewRequest("GET", abs_path, nil)
	req.Header.Add("X-Akamai-ACS-Action", action)
	api.auth(req, rel_path, action)
	resp, err := api.client.Do(req)
	if err != nil {
		err = errors.New(fmt.Sprintf("GET '%s' failed: %s", abs_path, err.Error()))
		return
	}
	if resp.StatusCode == http.StatusForbidden {
		err = NewHTTPError(resp)
		return
	}
	defer resp.Body.Close()

	decoder := xml.NewDecoder(resp.Body)

	// from http://grokbase.com/t/gg/golang-nuts/13bds55y8f/go-nuts-xml-parser
	decoder.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		// Windows-1252 is a superset of ISO-8859-1.
		if charset == "iso-8859-1" || charset == "ISO-8859-1" {
			return transform.NewReader(input, charmap.Windows1252.NewDecoder()), nil
		}
		return nil, fmt.Errorf("unsupported charset: %q", charset)
	}

	err = decoder.Decode(&listResp)
	if err != nil {
		err = errors.New(fmt.Sprintf("response of GET '%s' decode error: %s", abs_path, err.Error()))
	}
	return

}
