package utility

import (
	"os"
	"path/filepath"
)

// IsFile 判断是否为文件
func IsFile(path string) bool {
	abs, _ := filepath.Abs(path)
	if len(abs) == 0 {
		return false
	}
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	stat, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !stat.IsDir()
}
