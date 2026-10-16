package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"

	timeFormat = "02/Jan/2006:15:04:05 -0700"

	defaultLogName = "tls10proxy.log"

	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
	LevelFatal
)

func defaultLogPath() string {
	exe, err := os.Executable()
	if err != nil {
		return defaultLogName
	}

	return filepath.Join(filepath.Dir(exe), defaultLogName)
}

type Level int

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

func (l Level) color() string {
	switch l {
	case LevelDebug:
		return colorCyan
	case LevelInfo:
		return colorGreen
	case LevelWarn:
		return colorYellow
	case LevelError, LevelFatal:
		return colorRed
	default:
		return colorReset
	}
}

type Logger interface {
	Info(args ...interface{})
	Warn(args ...interface{})
	Error(args ...interface{})
	Debug(args ...interface{})
	Fatal(args ...interface{})

	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
}

// consoleLogger is the default Logger implementation.
type consoleLogger struct {
	mu sync.Mutex

	out   *os.File
	file  *os.File
	level Level
	color bool
}

// Option configures a consoleLogger.
type Option func(*consoleLogger)

func WithOutput(f *os.File) Option {
	return func(l *consoleLogger) {
		l.out = f
	}
}

func WithFile(f *os.File) Option {
	return func(l *consoleLogger) {
		l.file = f
	}
}

func WithLevel(level Level) Option {
	return func(l *consoleLogger) {
		l.level = level
	}
}

func WithColor(enabled bool) Option {
	return func(l *consoleLogger) {
		l.color = enabled
	}
}

func New(opts ...Option) Logger {
	l := &consoleLogger{
		out:   os.Stdout,
		level: LevelDebug,
		color: true,
	}

	for _, opt := range opts {
		opt(l)
	}

	return l
}

func newDefaultLogger() Logger {
	logPath := defaultLogPath()

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Keep console logging available if the log file cannot be opened.
		fmt.Fprintf(os.Stderr, "logger: unable to open %s: %v\n", defaultLogName, err)
		return New()
	}

	return New(WithFile(logFile))
}

func (l *consoleLogger) log(level Level, msg string) {
	if level < l.level {
		return
	}

	ts := time.Now().Format(timeFormat)
	prefix := fmt.Sprintf("[%s] [%s] ", ts, level)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.color && l.out != nil {
		fmt.Fprintf(l.out, "%s%s%s%s\n", level.color(), prefix, msg, colorReset)
	} else if l.out != nil {
		fmt.Fprintf(l.out, "%s%s\n", prefix, msg)
	}

	// File output is always plain text.
	if l.file != nil {
		fmt.Fprintf(l.file, "%s%s\n", prefix, msg)
	}
}

func (l *consoleLogger) Info(args ...interface{}) {
	l.log(LevelInfo, fmt.Sprint(args...))
}

func (l *consoleLogger) Warn(args ...interface{}) {
	l.log(LevelWarn, fmt.Sprint(args...))
}

func (l *consoleLogger) Error(args ...interface{}) {
	l.log(LevelError, fmt.Sprint(args...))
}

func (l *consoleLogger) Debug(args ...interface{}) {
	l.log(LevelDebug, fmt.Sprint(args...))
}

func (l *consoleLogger) Fatal(args ...interface{}) {
	l.log(LevelFatal, fmt.Sprint(args...))
	os.Exit(1)
}

func (l *consoleLogger) Infof(format string, args ...interface{}) {
	l.log(LevelInfo, fmt.Sprintf(format, args...))
}

func (l *consoleLogger) Warnf(format string, args ...interface{}) {
	l.log(LevelWarn, fmt.Sprintf(format, args...))
}

func (l *consoleLogger) Errorf(format string, args ...interface{}) {
	l.log(LevelError, fmt.Sprintf(format, args...))
}

func (l *consoleLogger) Debugf(format string, args ...interface{}) {
	l.log(LevelDebug, fmt.Sprintf(format, args...))
}

func (l *consoleLogger) Fatalf(format string, args ...interface{}) {
	l.log(LevelFatal, fmt.Sprintf(format, args...))
	os.Exit(1)
}

// ---- Default logger ----

var defaultLogger Logger = newDefaultLogger()

func Default() Logger { return defaultLogger }

func SetDefault(l Logger) { defaultLogger = l }

func Info(args ...interface{})  { defaultLogger.Info(args...) }
func Warn(args ...interface{})  { defaultLogger.Warn(args...) }
func Error(args ...interface{}) { defaultLogger.Error(args...) }
func Debug(args ...interface{}) { defaultLogger.Debug(args...) }
func Fatal(args ...interface{}) { defaultLogger.Fatal(args...) }

func Infof(format string, args ...interface{})  { defaultLogger.Infof(format, args...) }
func Warnf(format string, args ...interface{})  { defaultLogger.Warnf(format, args...) }
func Errorf(format string, args ...interface{}) { defaultLogger.Errorf(format, args...) }
func Debugf(format string, args ...interface{}) { defaultLogger.Debugf(format, args...) }
func Fatalf(format string, args ...interface{}) { defaultLogger.Fatalf(format, args...) }

// Ensure consoleLogger satisfies Logger at compile time.
var _ Logger = (*consoleLogger)(nil)
