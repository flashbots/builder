package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type PortInfo struct {
	LocalURL                string
	ServiceName             string
	ForwardedServiceAddress string
}

type ServiceInfo struct {
	UUID   string
	Name   string
	Ports  []PortInfo
	Status string
}

// parseUserServices parses the given text and returns a slice of ServiceInfo.
func parseUserServices(text string) ([]ServiceInfo, error) {
	var services []ServiceInfo

	// Split the text into lines for easier processing
	lines := strings.Split(text, "\n")

	var currentService *ServiceInfo

	// Iterate over each line
	for _, line := range lines {
		// Regular expression to match the service information
		serviceRe := regexp.MustCompile(`(?m)^([0-9a-f]{12})\s+(\S+)\s+(.*?)\s+(RUNNING|STOPPED)$`)
		portRe := regexp.MustCompile(`^\s*(\S+):\s+(\d+)/(\S+)\s+->\s+(.+)$`)
		defaultPortRe := regexp.MustCompile(`^\s*(\d+)/(\S+)\s+->\s+(.+)$`)

		if serviceRe.MatchString(line) {
			// Process the previous service and start a new one
			if currentService != nil {
				services = append(services, *currentService)
			}
			matches := serviceRe.FindStringSubmatch(line)
			currentService = &ServiceInfo{
				UUID:   matches[1],
				Name:   matches[2],
				Status: matches[4],
			}
			if matches[3] != "<none>" {
				if defaultPortRe.MatchString(matches[3]) {
					defaultPortMatches := defaultPortRe.FindStringSubmatch(matches[3])
					currentService.Ports = append(currentService.Ports, PortInfo{
						ServiceName:             currentService.Name,
						LocalURL:                defaultPortMatches[2],
						ForwardedServiceAddress: defaultPortMatches[3],
					})
				} else if portRe.MatchString(matches[3]) {
					portMatches := portRe.FindStringSubmatch(matches[3])
					currentService.Ports = append(currentService.Ports, PortInfo{
						ServiceName:             portMatches[1],
						LocalURL:                portMatches[3],
						ForwardedServiceAddress: portMatches[4],
					})
				}
			}
		} else if currentService != nil {
			if portRe.MatchString(line) {
				// If it's a named port for the current service
				portMatches := portRe.FindStringSubmatch(line)
				currentService.Ports = append(currentService.Ports, PortInfo{
					ServiceName:             portMatches[1],
					LocalURL:                portMatches[3],
					ForwardedServiceAddress: portMatches[4],
				})
			} else if defaultPortRe.MatchString(line) {
				// If it's an unnamed port for the current service
				defaultPortMatches := defaultPortRe.FindStringSubmatch(line)
				currentService.Ports = append(currentService.Ports, PortInfo{
					ServiceName:             currentService.Name,
					LocalURL:                defaultPortMatches[2],
					ForwardedServiceAddress: defaultPortMatches[3],
				})
			}
		}
	}

	// Append the last service if it exists
	if currentService != nil {
		services = append(services, *currentService)
	}

	return services, nil
}

// getBlockNumber sends a JSON-RPC request to the specified URL and returns the current block number
func getBlockNumber(url string) (int64, error) {
	jsonStr := []byte(`{"method":"eth_blockNumber","params":[],"id":1,"jsonrpc":"2.0"}`)

	// Create the HTTP request
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return 0, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("error sending request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("error reading response body: %w", err)
	}

	// Unmarshal the JSON response
	var response struct {
		Jsonrpc string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  string `json:"result"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return 0, fmt.Errorf("error unmarshaling response: %w", err)
	}

	// Convert hexadecimal result to integer
	blockNumber, err := strconv.ParseInt(response.Result, 0, 64)
	if err != nil {
		return 0, fmt.Errorf("error converting hex to int: %w", err)
	}

	return blockNumber, nil
}

func build(imageTag string, buildDir string, buildDockerfilePath string) {
	cmd := "docker build" +
		" -t " + imageTag +
		" -f " + buildDockerfilePath +
		" " + buildDir
	runCommand(cmd)
}

func update_config(imageTag string, imageArgs string, kurtosisNetworkScriptFolder string, slotTime int64, filename ...string) {
	// Determine the filename. If not provided, default to "network_params.json".
	var file string
	if len(filename) > 0 {
		file = filename[0]
	} else {
		file = "network_params.json"
	}

	// Read the file
	fileContent, err := os.ReadFile(file)
	if err != nil {
		fmt.Println("Error reading the file:", err)
		return
	}

	var data map[string]interface{}
	err = json.Unmarshal(fileContent, &data)
	if err != nil {
		fmt.Println("Error unmarshalling the JSON:", err)
		return
	}

	if slotTime != 0 {
		if networkParams, ok := data["network_params"].(map[string]interface{}); ok {
			networkParams["seconds_per_slot"] = slotTime
			fmt.Printf("Seconds per slot updated to %d\n", slotTime)
		} else {
			fmt.Println("network_params object not found or is not a JSON object")
		}
	}

	// Navigate to the participants array
	if participants, ok := data["participants"].([]interface{}); ok {
		for _, participant := range participants {
			p, ok := participant.(map[string]interface{})
			if !ok {
				fmt.Println("Error casting participant to map")
				continue
			}

			// Check if the participant is the one with "el_client_type": "geth"
			if p["el_client_type"] == "REPLACE_WITH_BUILDER" {
				p["el_client_type"] = "geth"
				// Modify the participant entry as needed
				p["el_client_image"] = imageTag

				if extraParamsInterface, ok := p["el_extra_params"].([]interface{}); ok {
					var extraParams []string
					for _, paramInterface := range extraParamsInterface {
						if param, ok := paramInterface.(string); ok {
							extraParams = append(extraParams, param)
						} else {
							fmt.Println("Error: el_extra_params contains a non-string value")
						}
					}
					extraParams = append(extraParams, imageArgs)
					p["el_extra_params"] = extraParams
				} else {
					fmt.Println("Error: el_extra_params is not an array of strings")
				}

				fmt.Println("Detected and updated BUILDER config: ", p)
				break // Exit the loop once the participant is found and updated
			}
		}
	} else {
		fmt.Println("Participants field not found or not an array")
		return
	}

	// Marshal the map back to JSON
	modifiedContent, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling the map back to JSON:", err)
		return
	}

	// Print out the resulting string
	fmt.Println(string(modifiedContent))

	// Save the modified content back to the file
	err = os.WriteFile(kurtosisNetworkScriptFolder+"/network_params_tmp.json", modifiedContent, os.ModePerm)
	if err != nil {
		fmt.Println("Error writing the modified content to the file:", err)
	}
}

func run(imageTag, imageArgs, enclaveName string, maxSteps int, kurtosisPath, kurtosisNetworkScriptFolder string, kurtosisNetConfigPath string, slotTime int64) {
	/*	params := map[string]interface{}{
		"image_tag":               imageTag,
		"image_args":              imageArgs,
		"enclave_name":            enclaveName,
		"max_steps":               maxSteps,
		"kurtosis_path":           kurtosisPath,
		"kurtosis_network_config": kurtosisNetworkScriptFolder,
	}*/
	update_config(imageTag, imageArgs, kurtosisNetworkScriptFolder, slotTime, kurtosisNetConfigPath)

	cmd := fmt.Sprintf("%s run --enclave %s %s", kurtosisPath, enclaveName, kurtosisNetworkScriptFolder)
	out, _, errRun := runCommand(cmd)
	if errRun != nil {
		fmt.Println("Error executting command:", errRun)
		return
	}

	services, errParse := parseUserServices(out)
	if errParse != nil {
		log.Fatalf("Error parsing services: %v", errParse)
	}

	printSummary(services)
	if maxSteps <= 0 {
		return
	}

	web3url := ""
	for _, service := range services {
		//fmt.Println(service.Name)
		if strings.HasPrefix(service.Name, "el-") {
			for _, port := range service.Ports {
				//fmt.Println(port.ServiceName)
				if strings.HasPrefix(port.ServiceName, "rpc") {
					//fmt.Println(port.ForwardedServiceAddress)
					web3url = port.ForwardedServiceAddress
					break // Break after printing the first matching LocalURL
				}
			}
			break // Break after checking the ports of the first matching service
		}
	}
	web3url = strings.TrimSpace(web3url)
	web3url = "http://" + web3url

	targetBlock := int64(maxSteps)

	block, err := getBlockNumber(web3url)

	if err != nil {
		fmt.Println("Error getting block number:", err)
		return
	}

	progressBarLength := 50 // Length of the progress bar

	for block < targetBlock {
		time.Sleep(1 * time.Second) // Delay to avoid rapid requests
		block, err = getBlockNumber(web3url)
		if err != nil {
			fmt.Println("\nError getting block number:", err)
			return
		}

		// Calculate progress
		progress := int(float64(block) / float64(targetBlock) * float64(progressBarLength))
		if progress > progressBarLength {
			progress = progressBarLength // Cap progress at 100%
		}

		percentage := int(float64(block) / float64(targetBlock) * 100)
		if percentage > 100 {
			percentage = 100 // Cap percentage at 100%
		}

		// Update progress bar with current block and percentage
		fmt.Printf("\rCurrent Block: %d, Progress: [%-50s] %d%%", block, strings.Repeat("=", progress)+strings.Repeat(" ", progressBarLength-progress), percentage)
	}

	fmt.Println("\nStopping all network related services")

	for _, service := range services {
		if service.Name != "grafana" && service.Name != "adminer" && service.Name != "postgres" && service.Name != "redis" && service.Name != "dora" && service.Name != "prometheus" {
			//fmt.Println(service.Name)
			cmd := fmt.Sprintf("%s service stop %s %s", kurtosisPath, enclaveName, service.Name)
			_, _, errRun := runCommand(cmd)
			if errRun != nil {
				fmt.Println("Error stopping service:", errRun)
				continue
			}
			//fmt.Println("Output:", out)
		}
	}
	fmt.Println("Stopped transaction spamming and block building services.")
	printSummary(services)
}

func printSummary(services []ServiceInfo) {
	fmt.Printf("\033[1m")
	fmt.Println("Please visit monitoring services for results:")
	for _, service := range services {
		if service.Name == "grafana" || service.Name == "dora" {
			for _, port := range service.Ports {
				web3url := port.ForwardedServiceAddress // Assuming ForwardedServiceAddress is the correct field
				web3url = strings.TrimSpace(web3url)
				// TODO: make the dashboard accessible at root
				if service.Name == "grafana" {
					web3url += "/d/geth-builder-overview/geth-builder-overview"
				}
				fmt.Printf("%s: %s   ", service.Name, web3url)
			}
		}
	}
	fmt.Printf("\033[0m\n")
}

func stop(kurtosisPath, enclaveName string) {
	if enclaveName == "" {
		fmt.Println("Error: enclave name must be specified.")
		cmd := fmt.Sprintf("%s enclave ls", kurtosisPath)
		runCommand(cmd)
		return
	}
	cmd := fmt.Sprintf("%s enclave rm -f %s", kurtosisPath, enclaveName)
	runCommand(cmd)
}

func runCommand(cmd string) (string, string, error) {
	var stdoutBuf, stderrBuf bytes.Buffer
	var command *exec.Cmd

	if runtime.GOOS == "windows" {
		command = exec.Command("cmd", "/C", cmd)
	} else {
		command = exec.Command("sh", "-c", cmd)
	}

	// Create multi-writers to write to both the buffer and the os.Stdout or os.Stderr
	stdoutMultiWriter := io.MultiWriter(&stdoutBuf, os.Stdout)
	stderrMultiWriter := io.MultiWriter(&stderrBuf, os.Stderr)

	command.Stdout = stdoutMultiWriter
	command.Stderr = stderrMultiWriter

	err := command.Start()
	if err != nil {
		return "", "", fmt.Errorf("command start failed: %v", err)
	}

	err = command.Wait()
	if err != nil {
		return stdoutBuf.String(), stderrBuf.String(), fmt.Errorf("command execution failed: %v", err)
	}

	return stdoutBuf.String(), stderrBuf.String(), nil
}

func help() {
	fmt.Println(`Emulate Network script
Available commands:
- build
  - -t           : Image tag (optional, default: "flashbots/builder:dev")
  - -d           : Image Build directory (optional, default: "..")
  - -f           : Build dockerfile path (optional, default: ../Dockerfile"), use "./Dockerfile.debug" for debug capabilities)
- run
  - -t           : Image tag (optional, default: "flashbots/builder:dev")
  - -n           : Enclave name (optional, default: "explorer")
  - -a           : Additional builder arguments (optional)
  - -s           : Max steps. Use -1 to run permanently (optional, default: 1000)
  - -k           : Kurtosis path (optional, default: "kurtosis")
  - -c           : Kurtosis network config (optional, default: "./kurtosis")
  - --slotTime   : Seconds per slot applied on local devnet (optional, default: 5)
- stop
  - -k           : Kurtosis path (optional, default: "kurtosis")
  - -n           : Enclave name (required)`)
}

func main() {
	flagSet := flag.NewFlagSet("", flag.ExitOnError)
	imageTag := flagSet.String("t", "flashbots/builder:dev", "Image tag for build or run.")
	enclaveName := flagSet.String("n", "explorer", "Enclave name for run or stop.")
	kurtosisPath := flagSet.String("k", "kurtosis", "Kurtosis path for run or stop.")

	if len(os.Args) < 2 {
		fmt.Println("Please provide a command. Available commands are: build, run, stop.")
		return
	}

	switch os.Args[1] {
	case "build":
		buildDir := flagSet.String("d", "..", "Build directory.")
		buildDockerfilePath := flagSet.String("f", "../Dockerfile", "Build dockerfile path. Use \"./Dockerfile.debug\" for debug capabilities")
		flagSet.Parse(os.Args[2:])
		build(*imageTag, *buildDir, *buildDockerfilePath)
	case "run":
		imageArgs := flagSet.String("a", "", "Image arguments for run.")
		maxSteps := flagSet.Int("s", 1000, "Max steps for run.")
		kurtosisNetworkConfigScriptFolder := flagSet.String("f", "./kurtosis", "Kurtosis network config for run.")
		kurtosisNetConfigPath := flagSet.String("c", "./kurtosis/network_params.json", "Kurtosis network params "+
			"configuration path. Note that run command modifies it with provided imageTag and imageArgs.")
		slotTime := flagSet.Int64("slotTime", 5, "Seconds per slot to update in the JSON config.")
		flagSet.Parse(os.Args[2:])
		run(*imageTag, *imageArgs, *enclaveName, *maxSteps, *kurtosisPath, *kurtosisNetworkConfigScriptFolder, *kurtosisNetConfigPath, *slotTime)
	case "stop":
		flagSet.Parse(os.Args[2:])
		stop(*kurtosisPath, *enclaveName)
	case "help":
		help()
	default:
		fmt.Println("Invalid command. Available commands are: build, run, stop.")
	}
}
