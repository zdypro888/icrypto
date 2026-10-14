package icrypto

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// 用实际生成的gRPC和HTTP适配器验证迁移，避免只改Go接口而遗漏线上路由/字段。
type nacTransportServer struct {
	UnimplementedCryptServiceServer
}

func (*nacTransportServer) NACInit(_ context.Context, req *NACInitRequest) (*NACInitResponse, error) {
	return &NACInitResponse{Request: append([]byte("request:"), req.Cert...)}, nil
}

func (*nacTransportServer) NACGenerateValidation(_ context.Context, req *NACGenerateValidationRequest) (*NACGenerateValidationResponse, error) {
	out := append(append([]byte(nil), req.Response...), req.SignData...)
	return &NACGenerateValidationResponse{ValidationData: out}, nil
}

func TestNACGRPCTransportPreservesBytes(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer()
	RegisterCryptServiceServer(server, &nacTransportServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient("passthrough:///nac-contract", grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := NewCryptServiceClient(conn)
	cert := []byte{0, 0xFF, 0x80, 1}
	init, err := client.NACInit(context.Background(), &NACInitRequest{Cert: cert})
	if err != nil || !bytes.Equal(init.GetRequest(), append([]byte("request:"), cert...)) {
		t.Fatalf("NACInit transport: %v", err)
	}
	response, data := []byte{0xA0, 0}, []byte{0xFE, 0x81}
	out, err := client.NACGenerateValidation(context.Background(), &NACGenerateValidationRequest{Response: response, SignData: data})
	if err != nil || !bytes.Equal(out.GetValidationData(), append(response, data...)) {
		t.Fatalf("NAC validation transport: %v", err)
	}
}

func TestNACHTTPRoutesAndFieldNumbers(t *testing.T) {
	mux := runtime.NewServeMux()
	if err := RegisterCryptServiceHandlerServer(context.Background(), mux, &nacTransportServer{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ route, body, key, want string }{
		{"/nac/init", `{"cert":"AP8="}`, "request", "request:\x00\xff"},
		{"/nac/generate-validation", `{"response":"AAE=","signData":"/4A="}`, "validationData", "\x00\x01\xff\x80"},
	} {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, tc.route, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		mux.ServeHTTP(recorder, req)
		var out map[string]string
		if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &out) != nil {
			t.Fatalf("%s: status %d", tc.route, recorder.Code)
		}
		got, err := base64.StdEncoding.DecodeString(out[tc.key])
		if err != nil || string(got) != tc.want {
			t.Fatalf("%s changed payload bytes", tc.route)
		}
	}
	for _, route := range []string{"/identity/session", "/identity/validation"} {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, route, strings.NewReader(`{}`)))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("retired route %s still accepted", route)
		}
	}
	// 重命名改变方法/路由，不改变仍使用字段的wire编号。
	fields := (&NACGenerateValidationRequest{}).ProtoReflect().Descriptor().Fields()
	if fields.ByName("response").Number() != 1 || fields.ByName("sign_data").Number() != 2 {
		t.Fatal("NAC response/sign_data wire field numbers changed")
	}
	if (&AbsintheActivateSessionRequest{}).ProtoReflect().Descriptor().Fields().ByName("handshake_response").Number() != 1 {
		t.Fatal("PSC handshake response wire field number changed")
	}
}
