package netstorage

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
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
	fmt.Println("writing to checksum")
	fmt.Println(data + sign_string)
	mac.Write([]byte(data + sign_string))
	signature = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return
}

// path: begin response output with noted subdirectory
func (api Api) List(cpcode uint, path string, limit uint) error {
	storage_group_name := ""

	host := storage_group_name + "-nsu.akamaihd.net"
	action := fmt.Sprintf("version=%s&action=list&format=xml&max_entries=%d", version, limit)
	rel_path := fmt.Sprintf("/%d/%s", cpcode, path)
	abs_path := "http://" + host + rel_path
	fmt.Println(abs_path)
	req, err := http.NewRequest("GET", abs_path, nil)
	req.Header.Add("X-Akamai-ACS-Action", action)
	api.auth(req, rel_path, action)
	resp, err := api.client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusForbidden {
		return NewHTTPError(resp)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println(body)
	return nil
}
