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
		percentage := calculatePercentage(score, 20)
		fmt.Printf("Password Strength Evaluation: %d%%\n", percentage)
		printPasswordStrength(score)
	}
	if err := input.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "Error reading standard input from user:", err)
	}
}

func checkPasswordStrength(password string) int {
	score := 0
	charTypesPresent := 0
	passwordLength := len(password)

	if passwordLength >= 12 {
		score += 4
	} else if passwordLength >= 8 {
		score += 2
	}

	// uppercase, lowercase, number & special character
	hasUpperCase, hasLowerCase, hasDigit, hasSpecialChar := checkCharTypes(password)

	if hasUpperCase {
		charTypesPresent++
	}
	if hasLowerCase {
		charTypesPresent++
	}
	if hasDigit {
		charTypesPresent++
	}
	if hasSpecialChar {
		charTypesPresent++
	}

	switch charTypesPresent {
	case 1:
		score++
	case 2:
		score += 3
	case 3:
		score += 5
	case 4:
		score += 8
	}

	if hasRepeatedChars(password) {
		score -= 2
	}

	// penalty for compromised password
	compromised, err := isCompromised(password)
	if err != nil {
		fmt.Println("Error checking for compromised password:", err)
	} else if compromised {
		score -= 3
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

func calculatePercentage(score int, length int) int {
	return (score * 100) / length
}

func printPasswordStrength(score int) {
	switch {
	case score < 5:
		fmt.Println("Password is weak.")
	case score < 10:
		fmt.Println("Password is moderate.")
	default:
		fmt.Println("Password is strong.")
	}
}

func checkPasswordStrength(password string) int {
	score := 0
	charTypesPresent := 0
	passwordLength := len(password)

	// if password length is 8 reward with 1 point if it is greater than or equal to 12 reward with 2 points
	if passwordLength >= 12 {
		score += 4
	} else if passwordLength >= 8 {
		score += 2
	}

	// uppercase, lowercase, number & special character
	hasUpperCase, hasLowerCase, hasDigit, hasSpecialChar := checkCharTypes(password)

	if hasUpperCase {
		charTypesPresent++
	}
	if hasLowerCase {
		charTypesPresent++
	}
	if hasDigit {
		charTypesPresent++
	}
	if hasSpecialChar {
		charTypesPresent++
	}

	switch charTypesPresent {
	case 1:
		score++
	case 2:
		score += 3
	case 3:
		score += 5
	case 4:
		score += 8
	}

	if hasRepeatedChars(password) {
		score -= 2
	}

	// penalty for compromised password
	compromised, err := isCompromised(password)
	if err != nil {
		fmt.Println("Error checking for compromised password:", err)
	} else if compromised {
		score -= 3
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

import (
	"fmt"
)

func checkPasswordStrength(password string) int {
	score := 0
	charTypesPresent := 0
	passwordLength := len(password)

	// if password length is 8 reward with 1 point if it is greaer than or equal to 12 reward with 2 points
	if passwordLength >= 12 {
		score += 4
	} else if passwordLength >= 8 {
		score += 2
	}
	
	// uppercase, lowercase, number & special character
	hasUpperCase, hasLowerCase, hasDigit, hasSpecialChar := checkCharTypes(password)

	if hasUpperCase {
		charTypesPresent++
	}
	if hasLowerCase {
		charTypesPresent++
	}
	if hasDigit {
		charTypesPresent++
	}
	if hasSpecialChar {
		charTypesPresent++
	}

	switch charTypesPresent {
	case 1:
		score++
	case 2:
		score += 3
	case 3:
		score += 5
	case 4:
		score += 8
	}

	if hasRepeatedChars(password) {
		score -= 2
	}

	// penalty for compromised password
	compromised, err := isCompromised(password)
	if err != nil {
		fmt.Println("Error checking for compromised password:", err)
	} else if compromised {
		score -= 3
	}


	return score
}


func checkCharTypes(password string) (bool, bool, bool, bool) {
	var hasUpperCase, hasLowerCase, hasDigit, hasSpecialChar bool
	for _, char := range password {
		if unicode.IsUpper(char) {
			hasUpperCase = true
		}
	}

func checkPasswordStrength(password string) int {
	score := 0
	charTypesPresent := 0
	passwordLength := len(password)

	// if password length is 8 reward with 1 point if it is greaer than or equal to 12 reward with 2 points
	if passwordLength >= 12 {
		score += 4
	} else if passwordLength >= 8 {
		score += 2
	}
	
	// uppercase, lowercase, number & special character
	hasUpperCase, hasLowerCase, hasDigit, hasSpecialChar := checkCharTypes(password)

	if hasUpperCase {
		charTypesPresent++
	}
	if hasLowerCase {
		charTypesPresent++
	}
	if hasDigit {
		charTypesPresent++
	}
	if hasSpecialChar {
		charTypesPresent++
	}

	switch charTypesPresent {
	case 1:
		score++
	case 2:
		score += 3
	case 3:
		score += 5
	case 4:
		score += 8
	}

	if hasRepeatedChars(password) {
		score -= 2
	}

	// penalty for compromised password
	compromised, err := isCompromised(password)
	if err != nil {
		fmt.Println("Error checking for compromised password:", err)
	} else if compromised {
		score -= 3
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