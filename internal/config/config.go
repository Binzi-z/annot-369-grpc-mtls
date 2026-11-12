// Package config 提供「环境变量 + 命令行」双来源的配置注册。
//
// 优先级：命令行 flag > 环境变量 > 代码默认值。
// 每个 flag 的默认值在注册时从对应环境变量读出，
// 因此 -h 输出里能看到当前生效来源。
package config

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// EnvPrefix 统一环境变量前缀，避免和别的进程打架。
const EnvPrefix = "ECHO_"

// String 注册一个 string flag，默认值来自环境变量 ECHO_<env>（缺省用 def）。
func String(name, env, def, usage string) *string {
	return flag.String(name, envVal(env, def), fmt.Sprintf("%s (env %s%s)", usage, EnvPrefix, env))
}

// Duration 同上，注册一个 duration flag（环境变量用 Go duration 语法，如 "2s"）。
func Duration(name, env string, def time.Duration, usage string) *time.Duration {
	d := def
	if v := os.Getenv(EnvPrefix + env); v != "" {
		parsed, err := time.ParseDuration(v)
		if err != nil {
			// 配置错误要尽早暴露，不要静默回退
			panic(fmt.Sprintf("invalid duration in %s%s: %q: %v", EnvPrefix, env, v, err))
		}
		d = parsed
	}
	return flag.Duration(name, d, fmt.Sprintf("%s (env %s%s)", usage, EnvPrefix, env))
}

func envVal(env, def string) string {
	if v := os.Getenv(EnvPrefix + env); v != "" {
		return v
	}
	return def
}
