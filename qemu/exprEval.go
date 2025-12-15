package qemu

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type SymbolResolver interface {
	ResolveRegister(name string) (uint64, error)
	ResolveSymbol(name string) (uint64, error)
}

func EvaluateExpression(expr string, resolver SymbolResolver) (uint64, error) {
	resolved, err := resolveSymbolsInExpr(expr, resolver)
	if err != nil {
		return 0, err
	}
	return evalArithmetic(resolved)
}

func resolveSymbolsInExpr(expr string, resolver SymbolResolver) (string, error) {
	symPattern := regexp.MustCompile(`\$([a-zA-Z_][a-zA-Z0-9_@.+-]*)`)

	var resolveErr error
	result := symPattern.ReplaceAllStringFunc(expr, func(match string) string {
		symName := strings.TrimPrefix(match, "$")
		val, err := resolver.ResolveRegister(symName)
		if err == nil {
			return fmt.Sprintf("0x%x", val)
		}
		val, err = resolver.ResolveSymbol(symName)
		if err == nil {
			return fmt.Sprintf("0x%x", val)
		}

		resolveErr = fmt.Errorf("failed to resolve symbol: %s", symName)
		return match
	})

	return result, resolveErr
}

func evalArithmetic(expr string) (uint64, error) {
	expr = strings.TrimSpace(expr)
	if !strings.ContainsAny(expr, "+-*/()") {
		return parseNumber(expr)
	}
	tokens := tokenize(expr)
	if len(tokens) == 0 {
		return 0, fmt.Errorf("empty expression")
	}
	result, _, err := parseAddSub(tokens, 0)
	return result, err
}

type token struct {
	typ   string
	value string
}

func tokenize(expr string) []token {
	var tokens []token
	expr = strings.ReplaceAll(expr, " ", "")

	i := 0
	for i < len(expr) {
		ch := expr[i]

		switch ch {
		case '+', '-', '*', '/':
			tokens = append(tokens, token{"op", string(ch)})
			i++
		case '(':
			tokens = append(tokens, token{"lparen", "("})
			i++
		case ')':
			tokens = append(tokens, token{"rparen", ")"})
			i++
		default:
			start := i
			if ch == '0' && i+1 < len(expr) && (expr[i+1] == 'x' || expr[i+1] == 'X') {
				i += 2
				for i < len(expr) && isHexDigit(expr[i]) {
					i++
				}
			} else {
				for i < len(expr) && (isDigit(expr[i])) {
					i++
				}
			}
			if i > start {
				tokens = append(tokens, token{"number", expr[start:i]})
			} else {
				i++
			}
		}
	}

	return tokens
}

func isDigit(ch byte) bool {
	return ch >= '0' && ch <= '9'
}

func isHexDigit(ch byte) bool {
	return isDigit(ch) || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
}

func parseAddSub(tokens []token, pos int) (uint64, int, error) {
	left, pos, err := parseMulDiv(tokens, pos)
	if err != nil {
		return 0, pos, err
	}

	for pos < len(tokens) && tokens[pos].typ == "op" && (tokens[pos].value == "+" || tokens[pos].value == "-") {
		op := tokens[pos].value
		pos++

		right, newPos, err := parseMulDiv(tokens, pos)
		if err != nil {
			return 0, pos, err
		}
		pos = newPos

		if op == "+" {
			left = left + right
		} else {
			if right > left {
				return 0, pos, fmt.Errorf("subtraction would result in negative number")
			}
			left = left - right
		}
	}

	return left, pos, nil
}

func parseMulDiv(tokens []token, pos int) (uint64, int, error) {
	left, pos, err := parseFactor(tokens, pos)
	if err != nil {
		return 0, pos, err
	}

	for pos < len(tokens) && tokens[pos].typ == "op" && (tokens[pos].value == "*" || tokens[pos].value == "/") {
		op := tokens[pos].value
		pos++

		right, newPos, err := parseFactor(tokens, pos)
		if err != nil {
			return 0, pos, err
		}
		pos = newPos

		if op == "*" {
			left = left * right
		} else {
			if right == 0 {
				return 0, pos, fmt.Errorf("division by zero")
			}
			left = left / right
		}
	}

	return left, pos, nil
}

func parseFactor(tokens []token, pos int) (uint64, int, error) {
	if pos >= len(tokens) {
		return 0, pos, fmt.Errorf("unexpected end of expression")
	}

	tok := tokens[pos]

	if tok.typ == "number" {
		val, err := parseNumber(tok.value)
		return val, pos + 1, err
	}

	if tok.typ == "lparen" {
		val, newPos, err := parseAddSub(tokens, pos+1)
		if err != nil {
			return 0, newPos, err
		}
		pos = newPos

		if pos >= len(tokens) || tokens[pos].typ != "rparen" {
			return 0, pos, fmt.Errorf("missing closing parenthesis")
		}

		return val, pos + 1, nil
	}

	return 0, pos, fmt.Errorf("unexpected token: %s", tok.value)
}

func parseNumber(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		return strconv.ParseUint(s[2:], 16, 64)
	}
	if strings.HasPrefix(s, "0") && len(s) > 1 {
		return strconv.ParseUint(s, 8, 64)
	}
	return strconv.ParseUint(s, 10, 64)
}

func ResolveSymbolsInCommand(cmd string, resolver SymbolResolver) (string, error) {
	if !strings.Contains(cmd, "$") {
		return cmd, nil
	}

	exprPattern := regexp.MustCompile(`(\$[a-zA-Z_][a-zA-Z0-9_@.+-]*(?:\s*[+\-*/]\s*(?:0[xX][0-9a-fA-F]+|0[0-7]+|[0-9]+|\$[a-zA-Z_][a-zA-Z0-9_@.+-]*))*)`)

	result := exprPattern.ReplaceAllStringFunc(cmd, func(match string) string {
		val, err := EvaluateExpression(match, resolver)
		if err != nil {
			resolved, err2 := resolveSymbolsInExpr(match, resolver)
			if err2 != nil {
				return match
			}
			return resolved
		}
		return fmt.Sprintf("0x%x", val)
	})

	return result, nil
}
