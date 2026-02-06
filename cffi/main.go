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

//export Free
func Free(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

func outPut(res *ja3.Response) *C.char {
	jsonResponse, err := json.Marshal(res)
	if err != nil {
		return C.CString(`{"Body":"json marshal error","StatusCode":0}`)
	}
	return C.CString(string(jsonResponse))
}

//export request
func request(params *C.char) *C.char {
	optionsStr := C.GoString(params)
	options := ja3.Ja3Request{}

	response := ja3.Response{}

	err := json.Unmarshal([]byte(optionsStr), &options)
	if err != nil {
		response.Body = "Invalid input JSON: " + err.Error()
		return outPut(&response)
	}

	res, err := client.DoRequest(&options)
	if err != nil {
		response.Body = "Request error: " + err.Error()
		return outPut(&response)
	}
	defer res.Body.Close()

	bodyBytes, err := io.ReadAll(res.Body)
	if err != nil {
		response.Body = "Read body error: " + err.Error()
		return outPut(&response)
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
	return outPut(&response)
}

func main() {}
