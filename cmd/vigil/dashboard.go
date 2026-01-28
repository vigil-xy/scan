package main

import (
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"time"

	"github.com/vigil-sec/vigil/pkg/dashboard"
)

func runDashboard() {
	fmt.Println("🚀 Starting Vigil Dashboard on http://localhost:8080")
	
	// Open browser automatically after brief delay
	go func() {
		time.Sleep(500 * time.Millisecond)
		openBrowser("http://localhost:8080")
	}()
	
	log.Fatal(dashboard.StartDashboardAPI())
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		fmt.Printf("Open your browser to: %s\n", url)
		return
	}
	
	if err := cmd.Start(); err != nil {
		fmt.Printf("Open your browser to: %s\n", url)
	}
}
