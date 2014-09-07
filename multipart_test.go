package pgpmail

import "testing"

func TestExtract(t *testing.T) {
	td := new(TestData)
	td.Subject = "Hello world"
	td.MultipartType = "alternative"
	td.Parts = []string{plainPart, htmlPart}
	m := td.Message()
	m.mpContent.parts[0].Body = insertCR("This is modified content.\n")
	m.packMultiparts()
	if m.String() != testMultipartModified {
		t.Error("modifed multipart message does not match expected output")
	}
}

var testMultipartModified = insertCR(`From: from@example.com
To: to@example.com, alice@example.com
Cc: bob@example.com
Subject: Hello world
Mime-Version: 1.0
Content-Type: multipart/alternative; boundary=001a11c167c8f1cb3104f8f4c019
Content-Transfer-Encoding: 7bit

--001a11c167c8f1cb3104f8f4c019
Content-Type: text/plain; charset=UTF-8

This is modified content.

--001a11c167c8f1cb3104f8f4c019
Content-Type: text/html; charset=UTF-8

<div dir="ltr">1234</div>

--001a11c167c8f1cb3104f8f4c019--
`)
