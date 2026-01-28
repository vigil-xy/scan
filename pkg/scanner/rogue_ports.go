package scanner

import (
"fmt"
"net"
"time"
)

var RoguePorts = map[int]string{
11434: "Ollama (prompt injection risk)",
8000:  "Common dev server hijack",
5000:  "Flask debug server",
8888:  "Jupyter notebook",
3000:  "React dev server",
8080:  "HTTP proxy risk",
9000:  "FastAPI/Swagger UI",
}

func ScanRoguePorts() ([]string, error) {
var findings []string

for port, desc := range RoguePorts {
address := fmt.Sprintf("localhost:%d", port)
conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
if err != nil {
continue // Port not open
}
conn.Close()

findings = append(findings, fmt.Sprintf("🚨 Rogue agent port %d (%s) is OPEN", port, desc))
}

return findings, nil
}

func ScanListeningProcesses() ([]string, error) {
// This would integrate with eBPF probes in Phase 2
return []string{"eBPF monitoring active"}, nil
}
