package main

import (
	"flag"
	"fmt"
	"time"
)

// run as
// go run breathe.go -duration 5 -width 8

func p(x int, mm int) {
	fmt.Printf("\033[0;0H[")
	for i := 0; i < x; i++ {
		fmt.Printf(" ")
	}
	fmt.Printf("*")
	for i := x; i < mm; i++ {
		fmt.Printf(" ")
	}
	fmt.Printf("]\n")
}

func do(L int, T int) {
	waitPerSymbol := time.Duration(T * 1000 / L)
	for i := 0; i < L; i++ {
		p(i, L-1)
		time.Sleep(waitPerSymbol * time.Millisecond)
	}
	for i := L - 2; i > 0; i-- {
		p(i, L-1)
		time.Sleep(waitPerSymbol * time.Millisecond)
	}
}

func main() {
	width := flag.Int("width", 11, "row width")
	duration := flag.Int("duration", 8, "cycle duration (in s)")
	flag.Parse()
	for {
		do(*width, *duration)
	}
}
