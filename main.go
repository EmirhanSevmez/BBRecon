package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fatih/color"
)

// --- Color Helpers ---
var (
	info     = color.New(color.FgCyan).PrintfFunc()
	success  = color.New(color.FgGreen).PrintfFunc()
	errColor = color.New(color.FgRed).PrintfFunc()
	yellow   = color.New(color.FgYellow).PrintfFunc()
)

// --- Required Tools & Installation Paths ---
var requiredTools = map[string]string{
	"subfinder":   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
	"assetfinder": "github.com/tomnomnom/assetfinder@latest",
	"subzy":       "github.com/PentestPad/subzy@latest",
	"katana":      "github.com/projectdiscovery/katana/cmd/katana@latest",
}

// --- Auto-Install Function ---
func checkAndInstallDependencies() {
	fmt.Println("--------------------------------------------------")
	info("[*] System Check: Verifying required tools...\n")

	// Ensure GOPATH/bin is in PATH for this process
	homeDir, _ := os.UserHomeDir()
	goBin := filepath.Join(homeDir, "go", "bin")
	pathEnv := os.Getenv("PATH")
	if !strings.Contains(pathEnv, goBin) {
		os.Setenv("PATH", goBin+string(os.PathListSeparator)+pathEnv)
	}

	for tool, url := range requiredTools {
		// Check if the tool exists in the system PATH
		path, err := exec.LookPath(tool)

		if err != nil {
			yellow("[!] '%s' not found. Installing automatically... (This may take a while)\n", tool)

			// Run: go install github.com/...@latest
			cmd := exec.Command("go", "install", url)
			cmd.Stdout = nil // Keep screen clean
			cmd.Stderr = os.Stderr

			installErr := cmd.Run()
			if installErr != nil {
				errColor("[-] ERROR: Failed to install %s. Please install it manually.\n", tool)
				errColor("[-] Detail: %v\n", installErr)
			} else {
				success("[+] %s installed successfully.\n", tool)
			}
		} else {
			fmt.Printf("    -> %s: OK (%s)\n", tool, path)
		}
	}

	// Exception: httpx-toolkit (Rename httpx -> httpx-toolkit to avoid conflict)
	if _, err := exec.LookPath("httpx-toolkit"); err != nil {
		yellow("[!] 'httpx-toolkit' not found. Installing 'httpx' and renaming...\n")

		cmd := exec.Command("go", "install", "github.com/projectdiscovery/httpx/cmd/httpx@latest")
		cmd.Stdout = nil
		cmd.Stderr = os.Stderr

		if err := cmd.Run(); err != nil {
			errColor("[-] ERROR: Failed to install httpx: %v\n", err)
		} else {
			// Rename httpx.exe -> httpx-toolkit.exe
			homeDir, _ := os.UserHomeDir()
			goBin := filepath.Join(homeDir, "go", "bin")
			src := filepath.Join(goBin, "httpx.exe")
			dst := filepath.Join(goBin, "httpx-toolkit.exe")

			// Remove destination if exists (unlikely if lookpath failed, but good practice)
			os.Remove(dst)

			if err := os.Rename(src, dst); err != nil {
				errColor("[-] Failed to rename binary: %v\n", err)
				errColor("    Manually rename %s to %s\n", src, dst)
			} else {
				success("[+] httpx-toolkit installed and configured.\n")
			}
		}
	} else {
		fmt.Printf("    -> httpx-toolkit: OK\n")
	}

	fmt.Println("--------------------------------------------------\n")
}

// --- Download SecretFinder ---
func checkAndDownloadSecretFinder() {
	if _, err := os.Stat("secretfinder.py"); os.IsNotExist(err) {
		yellow("[!] 'secretfinder.py' not found. Downloading...\n")
		url := "https://raw.githubusercontent.com/m4ll0k/SecretFinder/master/SecretFinder.py"

		resp, err := http.Get(url)
		if err != nil {
			errColor("[-] Error downloading SecretFinder: %v\n", err)
			return
		}
		defer resp.Body.Close()

		out, err := os.Create("secretfinder.py")
		if err != nil {
			errColor("[-] Error creating file: %v\n", err)
			return
		}
		defer out.Close()

		_, err = io.Copy(out, resp.Body)
		if err != nil {
			errColor("[-] Error saving SecretFinder: %v\n", err)
			return
		}
		success("[+] SecretFinder downloaded successfully.\n")
	}
}

func printBanner() {
	color.HiMagenta(`
   ______      ____                      
  / ____/___  / __ \___  _________  ____ 
 / / __/ __ \/ /_/ / _ \/ ___/ __ \/ __ \
/ /_/ / /_/ / _, _/  __/ /__/ /_/ / / / /
\____/\____/_/ |_|\___/\___/\____/_/ /_/ 
                                         
    v1.1 - Auto-Install & Recon Tool
    `)
	fmt.Println()
}

// --- Helper Functions ---

func runCommand(toolName string, args []string, outputFile string) {
	info("[*] Running: %s...\n", toolName)

	cmd := exec.Command(toolName, args...)

	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			errColor("[-] File creation error (%s): %v\n", toolName, err)
			return
		}
		defer f.Close()
		cmd.Stdout = f
	} else {
		cmd.Stdout = os.Stdout
	}

	cmd.Stderr = os.Stderr

	err := cmd.Run()
	if err != nil {
		errColor("[-] Error (%s): %v\n", toolName, err)
	} else {
		success("[+] %s completed.\n", toolName)
	}
}

func mergeAndUnique(filenames []string, outputFilename string) {
	yellow("[!] Merging files and removing duplicates...\n")

	uniqueMap := make(map[string]bool)
	counter := 0

	for _, filename := range filenames {
		f, err := os.Open(filename)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				uniqueMap[line] = true
			}
		}
		f.Close()
	}

	out, err := os.Create(outputFilename)
	if err != nil {
		return
	}
	defer out.Close()

	for domain := range uniqueMap {
		out.WriteString(domain + "\n")
		counter++
	}

	success("[+] Total Unique Subdomains: %d -> Saved to %s\n", counter, outputFilename)
}

func extractJS(inputFile string, outputFile string) {
	yellow("[!] Extracting .js files from crawl data...\n")

	f, err := os.Open(inputFile)
	if err != nil {
		return
	}
	defer f.Close()

	out, err := os.Create(outputFile)
	if err != nil {
		return
	}
	defer out.Close()

	scanner := bufio.NewScanner(f)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, ".js") {
			out.WriteString(line + "\n")
			count++
		}
	}
	success("[+] Found %d JS files -> Saved to %s\n", count, outputFile)
}

func runSecretFinder(jsFileList string) {
	yellow("[!] Starting SecretFinder (Python)...\n")

	// Check if secretfinder.py exists
	if _, err := os.Stat("secretfinder.py"); os.IsNotExist(err) {
		errColor("[-] ERROR: 'secretfinder.py' not found in the current directory.\n")
		return
	}

	f, err := os.Open(jsFileList)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		jsUrl := scanner.Text()
		fmt.Printf("   > Analyzing: %s\n", jsUrl)

		cmd := exec.Command("python3", "secretfinder.py", "-i", jsUrl, "-o", "cli")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Run()
	}
}

// --- Main Execution ---

func main() {
	// 0. Check and Install Dependencies
	checkAndInstallDependencies()
	checkAndDownloadSecretFinder()

	printBanner()
	time.Sleep(1 * time.Second)

	domainPtr := flag.String("d", "", "Target domain (e.g., example.com)")
	flag.Parse()

	if *domainPtr == "" {
		errColor("[-] Error: Domain is required.\n")
		info("Usage: go run main.go -d target.com\n")
		os.Exit(1)
	}

	target := *domainPtr

	// 1. Subdomain Discovery
	runCommand("subfinder", []string{"-d", target, "-o", "subfinder.txt"}, "")
	runCommand("assetfinder", []string{"--subs-only", target}, "assets.txt")

	// 2. Merge & Deduplicate
	mergeAndUnique([]string{"subfinder.txt", "assets.txt"}, "sub.txt")

	// 3. Live Check (Probing)
	runCommand("httpx-toolkit", []string{"-l", "sub.txt", "-o", "live.txt"}, "")

	// 4. Detailed Scan
	runCommand("httpx-toolkit", []string{
		"-l", "sub.txt",
		"-title", "-sc", "-cl", "-location", "-fr",
		"-o", "status.txt",
	}, "")

	// 5. Subdomain Takeover Check
	runCommand("subzy", []string{"run", "--targets", "sub.txt"}, "")

	// 6. Crawling (Katana)
	runCommand("katana", []string{"-u", "live.txt", "-o", "katana.txt"}, "")

	// 7. JS Extraction
	extractJS("katana.txt", "jsfiles.txt")

	// 8. Secret Analysis
	runSecretFinder("jsfiles.txt")

	fmt.Println()
	color.HiGreen("[!!!] All Recon Tasks Completed Successfully! [!!!]")
}
