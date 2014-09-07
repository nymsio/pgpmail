package pgpmail

import "testing"

func TestAddHeader(t *testing.T) {
	m := new(Message)
	m.AddHeader("foo", "bar")
	if len(m.HeaderList) != 1 {
		t.Error("HeaderList is not expected length: ", len(m.HeaderList))
	}
	if m.HeaderList[0].Value != "bar" {
		t.Error("HeaderList[0] is not expected value: ", m.HeaderList[0])
	}

}

var plainPart = `Content-Type: text/plain; charset=UTF-8

This is a test multipart message.`

var htmlPart = `Content-Type: text/html; charset=UTF-8

<div dir="ltr">1234</div>
`

func TestTemplates(t *testing.T) {
	body := "This is a test message."
	td := new(TestData)
	td.From = "meme@you.com"
	td.Body = body
	m := td.Message()
	if body != m.Body {
		t.Error("parsed message body does not match original body")
	}

	td = new(TestData)
	td.MultipartType = "alternative"
	td.Parts = []string{plainPart, htmlPart}
	m = td.Message()
	if m.mpContent.parts[0].Body != "This is a test multipart message." {
		t.Error("parsed multipart did not match original body")
	}
}
