package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"example.invalid/local-fixture/internal/endorsement"
)

// runInit 初始化离线存储目录与钥匙环（策略密钥 + 签注代次 1 密钥）。
func runInit(args []string) {
	fs := flagSet("init")
	dir := fs.String("dir", "", "存储目录（必填）")
	mustParse(fs, args)
	if *dir == "" {
		fail(fmt.Errorf("init 需要 -dir"))
	}
	if err := initStore(*dir); err != nil {
		fail(err)
	}
	fmt.Printf("已初始化 %s（策略密钥与签注 v1 密钥均为随机生成）\n", *dir)
}

func initStore(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	policy := make([]byte, 32)
	initial := make([]byte, 32)
	if _, err := rand.Read(policy); err != nil {
		return err
	}
	if _, err := rand.Read(initial); err != nil {
		return err
	}
	kr := endorsement.NewKeyring(policy, initial)
	return kr.Save(dir + "/" + keyringName)
}

// runAddKey 为钥匙环增加一个签注代次（旧代密钥保留，用于历史复验）。
func runAddKey(args []string) {
	fs := flagSet("addkey")
	dir := fs.String("dir", "", "存储目录")
	version := fs.Int("version", 0, "新签注代次（正整数）")
	mustParse(fs, args)
	if *dir == "" || *version <= 0 {
		fail(fmt.Errorf("addkey 需要 -dir 与正整数 -version"))
	}
	kr, err := loadKeyring(*dir)
	if err != nil {
		fail(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		fail(err)
	}
	if err := kr.AddVersion(*version, secret); err != nil {
		fail(err)
	}
	if err := kr.Save(*dir + "/" + keyringName); err != nil {
		fail(err)
	}
	fmt.Printf("已增加签注代次 %d（旧代密钥保留）\n", *version)
}
