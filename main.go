package main

import (
	"bufio"
	"fmt"
	"os"
	"unicode"
)

func main() {
	fmt.Println("Enter a password to check:")
	input := bufio.NewScanner(os.Stdin)
		if input.Scan() {
			password := input.Text()
			score := checkPasswordStrength(password)
			percentage := (score * 100) / 6
			// fmt.Printf("Password score: %d/5\n", score)
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
	if passwordLength >= 8 {
		score++
	} else if passwordLength >= 12 {
		score += 2
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