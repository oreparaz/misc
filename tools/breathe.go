package main

// run as
// go run breathe.go -duration 5 -width 8

import (
	"flag"
	"fmt"
	"strings"
	"time"
)

const (
	clearScreen = "\033[2J"
	moveCursor  = "\033[0;0H"
	colorCyan   = "\033[36m"
	colorReset  = "\033[0m"
)

func drawBar(pos, width int) {
	bar := strings.Repeat(" ", pos) + "●" + strings.Repeat(" ", width-pos)
	fmt.Printf("%s%s[%s%s%s]\n", moveCursor, colorCyan, bar, colorReset, colorCyan)
}

func breatheCycle(width, durationSec int) {
	delay := time.Duration(durationSec*1000/width) * time.Millisecond

	// Inhale
	for i := 0; i < width; i++ {
		drawBar(i, width-1)
		time.Sleep(delay)
	}
	// Exhale
	for i := width - 2; i > 0; i-- {
		drawBar(i, width-1)
		time.Sleep(delay)
	}
}

func main() {
	width := flag.Int("width", 11, "bar width")
	duration := flag.Int("duration", 8, "cycle duration in seconds")
	flag.Parse()

	fmt.Print(clearScreen)
	for {
		breatheCycle(*width, *duration)
	}
}
