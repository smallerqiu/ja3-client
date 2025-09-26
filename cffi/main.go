package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"io"
	"unsafe"

	client "github.com/smallerqiu/ja3-client"
	ja3 "github.com/smallerqiu/ja3-client/ja3"
)

func outPut(res *ja3.Response, error bool) *C.char {
	if error {
		// res.StatusCode = 0
	}
	jsonResponse, err := json.Marshal(res)
	if err != nil {
		return C.CString(`{"Body":"` + err.Error() + `","StatusCode":0}`)
	}

	respStr := C.CString(string(jsonResponse))

	defer C.free(unsafe.Pointer(respStr))
	return respStr
}

//export request
func request(params *C.char) *C.char {
	response := ja3.Response{}
	optionsStr := C.GoString(params)
	options := ja3.Ja3Request{}
	err := json.Unmarshal([]byte(optionsStr), &options)
	if err != nil {
		response.Body = err.Error()
		return outPut(&response, true)
	}
	res, err := client.DoRequest(&options)

	if err != nil {
		response.Body = err.Error()
		return outPut(&response, true)
	}
	defer res.Body.Close()
	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		response.Body = err.Error()
		return outPut(&response, false)
	}

	cookiesMap := make(map[string]string)
	for _, cookie := range res.Cookies() {
		cookiesMap[cookie.Name] = cookie.Value
	}

	response = ja3.Response{
		StatusCode: res.StatusCode,
		Body:       string(bodyBytes),
		Headers:    res.Header,
		Cookies:    cookiesMap,
	}
	return outPut(&response, false)
}
func main() {}
