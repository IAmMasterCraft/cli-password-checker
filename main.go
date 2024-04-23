package main

import (
	"bufio"
	"fmt"
	"os"
	"unicode"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"errors"
	"time"
)

func main() {
	fmt.Println("Enter a password to check:")
    input := bufio.NewScanner(os.Stdin)
    if input.Scan() {
        password := input.Text()
        score, err := checkPasswordStrength(password)
        if err != nil {
            fmt.Fprintf(os.Stderr, "Error checking password strength: %v\n", err)
            return
        }
        percentage := (score * 100) / 20
        fmt.Printf("Password Strength Evaluation: %d%%\n", percentage)
        classifyPassword(score)
    }
    if err := input.Err(); err != nil {
        fmt.Fprintf(os.Stderr, "Error reading standard input: %v\n", err)
    }
}

func checkPasswordStrength(password string) (int, error) {
	score, err := evaluatePassword(password)
	if err != nil {
		return 0, fmt.Errorf("error evaluating password: %w", err)
	}

	compromised, err := isCompromised(password)
	if err != nil {
		return score, fmt.Errorf("error checking if password is compromised: %w", err)
	} else if compromised {
		score -= 3
	}

	return score, nil
}

func evaluatePassword(password string) (int, error) {
    score := 0
    typesPresent := 0

    hasUpperCase, hasLowerCase, hasDigit, hasSpecialChar := checkCharTypes(password)
    if hasUpperCase {
        typesPresent++
    }
    if hasLowerCase {
        typesPresent++
    }
    if hasDigit {
        typesPresent++
    }
    if hasSpecialChar {
        typesPresent++
    }

    score += calculateDiversityScore(typesPresent)

    if hasRepeatedChars(password) {
        return score, errors.New("password has repeated characters")
    }
    return score, nil
}

func calculateDiversityScore(typesPresent int) int {
    switch typesPresent {
    case 1:
        return 1
    case 2:
        return 3
    case 3:
        return 5
    case 4:
        return 8
    default:
        return 0
    }
}

func checkCharTypes(password string) (bool, bool, bool, bool) {
	var hasUpperCase, hasLowerCase, hasDigit, hasSpecialChar bool
	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUpperCase = true
		}
		if unicode.IsLower(char) {
			hasLowerCase = true
		}
		if unicode.IsDigit(char) {
			hasDigit = true
		}
		if unicode.IsPunct(char) || unicode.IsSymbol(char) {
			hasSpecialChar = true
		}
	}
	return hasUpperCase, hasLowerCase, hasDigit, hasSpecialChar
}

func hasRepeatedChars(password string) bool {
	var previous rune
	for i, char := range password {
		if i > 0 && char == previous {
			return true
		}
		previous = char
	}
	return false
}

func sha1Hash(text string) string {
	hasher := sha1.New()
	hasher.Write([]byte(text))
	return strings.ToUpper(hex.EncodeToString(hasher.Sum(nil)))
}

func isCompromised(password string) (bool, error) {
	hash := sha1Hash(password)
    prefix := hash[:5]
    suffix := hash[5:]
    url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)

    var body []byte
    var err error
    maxRetries := 3
    backoff := time.Millisecond * 500

    for i := 0; i < maxRetries; i++ {
        body, err = makeHTTPRequest(url)
        if err == nil {
            return checkHash(suffix, body), nil
        }
        time.Sleep(backoff)
        backoff *= 2 // Double the backoff interval
    }

    return false, fmt.Errorf("failed after retries: %w", err)
}

func checkHash(suffix string, body []byte) bool {
    hashes := strings.Split(string(body), "\r\n")
    for _, line := range hashes {
        parts := strings.Split(line, ":")
        if len(parts) > 0 && strings.ToUpper(parts[0]) == suffix {
            return true
        }
    }
    return false
}

func makeHTTPRequest(url string) ([]byte, error) {
    client := &http.Client{
        Timeout: time.Second * 10, // 10 seconds timeout
    }
    response, err := client.Get(url)
    if err != nil {
        return nil, fmt.Errorf("HTTP request failed: %w", err)
    }
    defer response.Body.Close()

    body, err := io.ReadAll(response.Body)
    if err != nil {
        return nil, fmt.Errorf("failed to read HTTP response: %w", err)
    }
    return body, nil
}

func classifyPassword(score int) {
	switch {
	case score < 5:
		fmt.Println("Password is weak.")
	case score < 10:
		fmt.Println("Password is moderate.")
	default:
		fmt.Println("Password is strong.")
	}
}
