package pgpmail

import (
	"bytes"
	"text/template"
)

type TestData struct {
	From           string
	To             string
	Subject        string
	Body           string
	MultipartType  string
	MultipartExtra string
	Parts          []string
	Preamble       string
}

const defaultFrom = "from@example.com"
const defaultTo = "to@example.com, alice@example.com"
const defaultSubject = "Test Message"

func (tdata *TestData) Message() *Message {
	r := NewReader(tdata.String())
	m, err := r.ReadMessage()
	if err != nil {
		panic("error parsing message from template: " + err.Error())
	}
	return m
}

func (tdata *TestData) String() string {
	if tdata.From == "" {
		tdata.From = defaultFrom
	}
	if tdata.To == "" {
		tdata.To = defaultTo
	}
	if tdata.Subject == "" {
		tdata.Subject = defaultSubject
	}
	t := createTemplate(tdata)
	b := new(bytes.Buffer)
	t.Execute(b, tdata)
	return insertCR(b.String())
}

func createTemplate(tdata *TestData) *template.Template {
	if len(tdata.Parts) > 0 && tdata.MultipartType != "" {
		return template.Must(template.New("multipart").Parse(multipartTemplate))
	}
	return template.Must(template.New("simple").Parse(simpleTemplate))
}

var multipartTemplate = `From: {{.From}}
To: {{.To}}
Cc: bob@example.com
Subject: {{.Subject}}
Mime-Version: 1.0
Content-Type: multipart/{{.MultipartType}}; boundary=001a11c167c8f1cb3104f8f4c019{{if .MultipartExtra}}; {{.MultipartExtra}}{{end}}
Content-Transfer-Encoding: 7bit
{{if .Preamble}}
{{.Preamble}}{{end}}{{range $part := .Parts}}
--001a11c167c8f1cb3104f8f4c019
{{$part}}{{end}}
--001a11c167c8f1cb3104f8f4c019--`

var simpleTemplate = `From: {{.From}}
To: {{.To}}
Subject: {{.Subject}}
Mime-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

{{.Body}}`
