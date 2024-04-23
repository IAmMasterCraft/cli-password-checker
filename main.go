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
)

func main() {
	fmt.Println("Enter a password to check:")
	input := bufio.NewScanner(os.Stdin)
		if input.Scan() {
			password := input.Text()
			score := checkPasswordStrength(password)
			percentage := (score * 100) / 6
			// fmt.Printf for "(score * 100) / 6 = 100%"
			fmt.Printf("Password Strength Evaluation: %d%%\n", percentage)
	        if score < 3 {
	            fmt.Println("Password is weak.")
	        } else if score < 4 {
	            fmt.Println("Password is moderate.")
	        } else {
	            fmt.Println("Password is strong.")
	        }
		}
	if err := input.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
}

func checkPasswordStrength(password string) int {
	score := 0
	passwordLength := len(password)

	// if password length is 8 reward with 1 point if it is greaer than or equal to 12 reward with 2 points
	if passwordLength >= 12 {
		score += 2
	} else if passwordLength >= 8 {
		score ++
	}
	
	// uppercase, lowercase, number & special character
	hasUpperCase, hasLowerCase, hasDigit, hasSpecialChar := checkCharTypes(password)

	if hasUpperCase {
		score++
	}
	if hasLowerCase {
		score++
	}
	if hasDigit {
		score++
	}
	if hasSpecialChar {
		score++
	}

	if hasRepeatedChars(password) {
		score--
	}

	// penalty for compromised password
	compromised, err := isCompromised(password)
	if err != nil {
		fmt.Println("Error checking for compromised password:", err)
	} else if compromised {
		score--
	}


	return score
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
	response, err := http.Get(url)
	if err != nil {
		return false, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	hashes := strings.Split(string(body), "\r\n")
	for _, line := range hashes {
		parts := strings.Split(line, ":")
		if len(parts) > 0 && strings.ToUpper(parts[0]) == suffix {
			return true, nil
		}
	}
	return false, nil
}