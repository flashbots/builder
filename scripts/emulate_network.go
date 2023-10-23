package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"runtime"
	"sync"
)

func build(imageTag string, buildDir string, buildDockerfilePath string) {
	cmd := "docker build" +
		" -t " + imageTag +
		" -f " + buildDockerfilePath +
		" " + buildDir
	runCommand(cmd)
}

func update_config(imageTag string, imageArgs string, kurtosisNetworkScriptFolder string, filename ...string) {
	// Determine the filename. If not provided, default to "network_params.json".
	var file string
	if len(filename) > 0 {
		file = filename[0]
	} else {
		file = "network_params.json"
	}

	// Read the file
	fileContent, err := ioutil.ReadFile(file)
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
	err = ioutil.WriteFile(kurtosisNetworkScriptFolder+"/network_params_tmp.json", modifiedContent, os.ModePerm)
	if err != nil {
		fmt.Println("Error writing the modified content to the file:", err)
	}
}

func run(imageTag, imageArgs, enclaveName string, maxSteps int, kurtosisPath, kurtosisNetworkScriptFolder string, kurtosisNetConfigPath string) {
	/*	params := map[string]interface{}{
		"image_tag":               imageTag,
		"image_args":              imageArgs,
		"enclave_name":            enclaveName,
		"max_steps":               maxSteps,
		"kurtosis_path":           kurtosisPath,
		"kurtosis_network_config": kurtosisNetworkScriptFolder,
	}*/
	update_config(imageTag, imageArgs, kurtosisNetworkScriptFolder, kurtosisNetConfigPath)

	cmd := fmt.Sprintf("%s run --enclave %s %s", kurtosisPath, enclaveName, kurtosisNetworkScriptFolder)
	runCommand(cmd)
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

func runCommand(cmd string) {
	var command *exec.Cmd
	if runtime.GOOS == "windows" {
		fmt.Println("Running on Windows:", cmd)
		command = exec.Command("cmd", "/C", cmd)
	} else {
		fmt.Println("Running:", cmd)
		command = exec.Command("sh", "-c", cmd)
	}

	stdoutPipe, err := command.StdoutPipe()
	if err != nil {
		fmt.Printf("Error obtaining stdout: %v\n", err)
		return
	}

	stderrPipe, err := command.StderrPipe()
	if err != nil {
		fmt.Printf("Error obtaining stderr: %v\n", err)
		return
	}

	err = command.Start()
	if err != nil {
		fmt.Printf("Command start failed: %v\n", err)
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stdoutPipe)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()

	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			fmt.Println(scanner.Text())
		}
	}()

	wg.Wait()

	err = command.Wait()
	if err != nil {
		fmt.Printf("Command execution failed: %v\n", err)
	}
}

func help() {
	fmt.Println(`Emulate Network script
Available commands:
- build
  - -t : Image tag (optional, default: "flashbots/builder:dev")
  - -d : Image Build directory (optional, default: "..")
  - -f : Build dockerfile path (optional, default: "./Dockerfile.debug")
- run
  - -t : Image tag (optional, default: "flashbots/builder:dev")
  - -n : Enclave name (optional, default: "explorer")
  - -a : Additional builder arguments (optional)
  - -s : Max steps (optional, default: -1)
  - -k : Kurtosis path (optional, default: "kurtosis")
  - -c : Kurtosis network config (optional, default: "./kurtosis")
- stop
  - -k : Kurtosis path (optional, default: "kurtosis")
  - -n : Enclave name (required)
`)
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
		buildDockerfilePath := flagSet.String("f", "./Dockerfile.debug", "Build dockerfile path.")
		flagSet.Parse(os.Args[2:])
		build(*imageTag, *buildDir, *buildDockerfilePath)
	case "run":
		imageArgs := flagSet.String("a", "", "Image arguments for run.")
		maxSteps := flagSet.Int("s", -1, "Max steps for run.")
		kurtosisNetworkConfigScriptFolder := flagSet.String("f", "./kurtosis", "Kurtosis network config for run.")
		kurtosisNetConfigPath := flagSet.String("c", "./kurtosis/network_params.json", "Kurtosis network params "+
			"configuration path. Note that run command modifies it with provided imageTag and imageArgs.")
		flagSet.Parse(os.Args[2:])
		run(*imageTag, *imageArgs, *enclaveName, *maxSteps, *kurtosisPath, *kurtosisNetworkConfigScriptFolder, *kurtosisNetConfigPath)
	case "stop":
		flagSet.Parse(os.Args[2:])
		stop(*kurtosisPath, *enclaveName)
	case "help":
		help()
	default:
		fmt.Println("Invalid command. Available commands are: build, run, stop.")
	}
}
