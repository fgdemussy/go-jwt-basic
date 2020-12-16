package auth

import (
	"net/http"
	"testing"
)

func Test_extract(t *testing.T) {
	type args struct {
		r *http.Request
	}
	h := http.Header{
		"Authorization": {"Bearer some-token"},
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{"should return empty string given no auth header", args{&http.Request{}}, ""},
		{"should return payload given Authorization header", args{&http.Request{Header: h}}, "some-token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extract(tt.args.r); got != tt.want {
				t.Errorf("extract() = '%v', want '%v'", got, tt.want)
			}
		})
	}
}
