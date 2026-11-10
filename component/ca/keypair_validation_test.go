package ca

import (
	C "github.com/metacubex/mihomo/constant"
	"os"
	"path/filepath"
	"testing"
)

// 作者 long：读取成功不代表PEM中存在有效证书，空池不能冒充信任链校验成功。
func TestLoadCertificatesRejectsReadableInvalidPEMFile(t *testing.T) {
	root := t.TempDir()
	prior := C.Path.HomeDir()
	C.SetHomeDir(root)
	t.Cleanup(func() { C.SetHomeDir(prior) })
	file := filepath.Join(root, "invalid-ca.pem")
	if err := os.WriteFile(file, []byte("not a PEM certificate"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertificates(file); err == nil {
		t.Fatal("readable invalid certificate was accepted")
	}
}

// 作者 long：拒绝坏文件的修复不能误伤已存在的有效PEM信任证书。
func TestLoadCertificatesAcceptsReadableValidPEMFile(t *testing.T) {
	root := t.TempDir()
	prior := C.Path.HomeDir()
	C.SetHomeDir(root)
	t.Cleanup(func() { C.SetHomeDir(prior) })
	cert, _, _, err := NewRandomTLSKeyPair(KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "valid-ca.pem")
	if err = os.WriteFile(file, []byte(cert), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadCertificates(file); err != nil {
		t.Fatal("valid certificate file rejected")
	}
}
