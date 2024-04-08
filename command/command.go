package command

import (
	"fmt"
	"os"
)

// 获取命令行参数
func GetDomain() (string, error) {
	args := os.Args
	if len(args) != 2 {
		return "", fmt.Errorf("go run main.go {domain}")
	}
	return args[1], nil
}
