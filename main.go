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
			percentage := (score * 100) / 5
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
	if len(password) >= 8 {
		score++
	}
	// uppercase, lowercase, number & special character
	var hasUpperCase, hasLowerCase, hasNumber, hasSpecialChar bool

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpperCase = true
		case unicode.IsLower(char):
			hasLowerCase = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecialChar = true
		}
	}

	if hasUpperCase {
		score++
	}
	if hasLowerCase {
		score++
	}
	if hasNumber {
		score++
	}
	if hasSpecialChar {
		score++
	}

	return score
}
