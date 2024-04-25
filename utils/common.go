package utils

import (
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/rpc"
	"net/http"
	"time"
)

// ResponseData struct to hold data field from response
type ResponseData struct {
	BlockNbr int64  `json:"block_nbr"`
	MaxBid   string `json:"max_bid"` // bigint
	Builder  string `json:"builder"`
}

// Response struct to hold entire response structure
type Response struct {
	Status int          `json:"status"`
	Code   string       `json:"code"`
	Data   ResponseData `json:"data"`
}

// GetMaxBidData function to fetch MaxBid data for a given block number
func GetMaxBidData(blockNumber rpc.BlockNumber) (*ResponseData, error) {
	// API endpoint URL
	apiURL := fmt.Sprintf(GET_MAX_BID_URL, blockNumber)

	// Initialize HTTP client with timeout
	client := &http.Client{
		Timeout: DEFAULT_TIME_OUT * time.Second,
	}

	// Make GET request to API
	resp, err := client.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Check response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	// Decode response JSON
	var response Response
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response JSON: %v", err)
	}

	// Check status code
	if response.Status != 200 {
		return nil, fmt.Errorf("API request failed with status code: %d, code: %s", response.Status, response.Code)
	}

	// Return response data
	return &response.Data, nil
}
