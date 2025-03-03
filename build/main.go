package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"io"
	"runtime"
	"unsafe"

	ja3 "github.com/smallerqiu/ja3-client"
)

func outPutError(err error) *C.char {
	response := ja3.Response{
		StatusCode: 500,
		Body:       err.Error(),
		Headers:    nil,
		Cookies:    nil,
	}

	jsonResponse, err := json.Marshal(response)
	if err != nil {
		return C.CString(err.Error())
	}

	respStr := C.CString(string(jsonResponse))

	defer C.free(unsafe.Pointer(respStr))
	return respStr
}

//export request
func request(requestParams *C.char) *C.char {
	paramsStr := C.GoString(requestParams)
	params := ja3.Ja3Request{}
	err := json.Unmarshal([]byte(paramsStr), &params)
	if err != nil {
		return outPutError(err)
	}

	client, req, err := ja3.CreateSession(&params)

	if err != nil {
		return outPutError(err)
	}
	resp, err := client.Do(req)
	defer client.CloseIdleConnections()

	if err != nil {
		return outPutError(err)
	}

	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return outPutError(err)
	}

	cookiesMap := make(map[string]string)
	for _, cookie := range resp.Cookies() {
		cookiesMap[cookie.Name] = cookie.Value
	}

	response := ja3.Response{
		StatusCode: resp.StatusCode,
		Body:       string(bodyBytes),
		Headers:    resp.Header,
		Cookies:    cookiesMap,
	}

	respByte, err := json.Marshal(response)
	if err != nil {
		return outPutError(err)
	}

	respStr := C.CString(string(respByte))
	// defer C.free(unsafe.Pointer(respStr))
	runtime.SetFinalizer(respStr, func(ptr *C.char) {
		C.free(unsafe.Pointer(ptr))
	})
	return respStr
}
func main() {}
