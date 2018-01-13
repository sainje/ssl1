package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Result struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
}

func display(result Result) {
	data, _ := json.Marshal(result)
	fmt.Println(string(data))
}

func fileExist(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func checkFile(filePath string, ext string) bool {
	if strings.Index(filePath, ext) < 0 {
		return false
	}

	bl, _ := fileExist(filePath)
	if bl == false {
		return false
	}

	return true
}

func checkFileName(fileName string, ext string) bool {
	if strings.Index(fileName, ext) < 0 {
		return false
	}
	return true
}

func main() {
	//test()
	doConvert()
	time.Sleep(time.Microsecond * 1)
}

func test() {
	var result Result
	var certp12 string = "cert.p12"
	var keyp12 string = "key.p12"
	var p12pass string = "liandong"
	var certpem string = "f:/ttt/cert.pem"
	var keypem string = "f:/ttt/key.pem"
	var tmppass string = p12pass
	err := p12ToPem(certp12, keyp12, p12pass, certpem, keypem, tmppass)
	if err == nil {
		result.Code = 1
		result.Msg = "success"
		display(result)
	} else {
		result.Msg = err.Error()
		display(result)
	}
}

func doConvert() {
	var result Result

	p := os.Args
	if p == nil || len(p) != 6 {
		result.Msg = "params error"
		display(result)
	} else {
		var certp12 string = p[1]
		var keyp12 string = p[2]
		var p12pass string = p[3]
		var certpem string = p[4]
		var keypem string = p[5]
		var tmppass string = p12pass

		if checkFile(certp12, "p12") == false {
			result.Msg = "p12 cert file name or path error"
			display(result)
		} else if checkFile(keyp12, "p12") == false {
			result.Msg = "p12 key file name or path error"
			display(result)
		} else if checkFileName(certpem, "pem") == false {
			result.Msg = "pem cert file name or path error"
			display(result)
		} else if checkFileName(keypem, "pem") == false {
			result.Msg = "pem key file name or path error"
			display(result)
		} else {
			err := p12ToPem(certp12, keyp12, p12pass, certpem, keypem, tmppass)
			if err == nil {
				result.Code = 1
				result.Msg = "success"
				display(result)
			} else {
				result.Msg = err.Error()
				display(result)
			}
		}
	}
}

func p12ToPem(certp12, keyp12, p12pass, certpem, keypem, tmppass string) error {

	var tmpkeypem string = "tmpkey.pem"
	if strings.Index(keypem, "/") >= 0 {
		ps := strings.Split(keypem, "/")
		n := len(ps) - 1
		var dir string
		for i := 0; i < n; i++ {
			dir = dir + ps[i] + "/"
		}
		tmpkeypem = dir + tmpkeypem
	}

	//fmt.Println(tmpkeypem)

	//生成临时文件cert.pem，注意passin 和 passout 选项
	//openssl pkcs12 -clcerts -nokeys -out $newcert -in $cert  -passin pass:$passwd &&
	//openssl pkcs12 -clcerts -nokeys -out cert.pem -in cert.p12 -passin pass:P12_PASS
	cmd := exec.Command("openssl", "pkcs12", "-clcerts", "-nokeys", "-out", certpem, "-in", certp12, "-passin", "pass:"+p12pass)
	err := cmd.Run()
	if err != nil {
		//fmt.Println("err:" + err.Error())
		return err
	}

	time.Sleep(time.Microsecond * 1)

	//生成临时文件key.pem
	//openssl pkcs12 -nocerts -out $tmp -in $key -passin pass:$passwd -passout pass:$passwd &&
	//openssl pkcs12 -nocerts  -out key.pem -in key.p12 -passin pass:P12_PASS -passout pass:TMP_PASS
	cmd2 := exec.Command("openssl", "pkcs12", "-nocerts", "-out", tmpkeypem, "-in", keyp12, "-passin", "pass:"+p12pass, "-passout", "pass:"+tmppass)
	err2 := cmd2.Run()
	if err2 != nil {
		//fmt.Println("err2:" + err2.Error())
		return err2
	}

	time.Sleep(time.Microsecond * 1)

	//去掉tmpkey.pem的密码
	//openssl rsa -in $tmp -out $newkey -passin pass:$passwd  &&
	//openssl rsa -in key.pem -out key.unencrypted.pem -passin pass:TMP_PASS
	cmd3 := exec.Command("openssl", "rsa", "-in", tmpkeypem, "-out", keypem, "-passin", "pass:"+tmppass)
	err3 := cmd3.Run()
	if err3 != nil {
		//fmt.Println("err3:" + err3.Error())
		return err3
	}

	return nil
}
