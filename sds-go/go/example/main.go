package main

import (
	"fmt"

	sds "github.com/DataDog/dd-sensitive-data-scanner/sds-go/go"
)

func main() {
	rules := []sds.RuleConfig{
		sds.NewMatchingRule("hello", "hello", sds.ExtraConfig{}),
		sds.NewMatchingRule("world", "(?i)WoRlD", sds.ExtraConfig{}),
		sds.NewRedactingRule("secret", "se..et", "[REDACTED]", sds.ExtraConfig{}),
		sds.NewHashRule("hash", "apikey", sds.ExtraConfig{}),
	}

	scanner, err := sds.CreateScanner(rules)
	if err != nil {
		fmt.Println("err:", err, "\nexit.")
		return
	}

	fmt.Println("Created a scanner with rules:")
	fmt.Println("Starting to process logs")
	fmt.Println()

	if result, err := scanner.Scan([]byte("nothing to match")); err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%+v\n", result.Matches)
		fmt.Println("no match, should return an empty set of rule and string:", string(result.Event))
		fmt.Println("mutated:", result.Mutated)
		fmt.Println()
	}

	if result, err := scanner.Scan([]byte("hello WORLD, this log has one secret and contains all matches.")); err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%+v\n", result.Matches)
		fmt.Println("processed:", string(result.Event))
		fmt.Println("mutated:", result.Mutated)
		fmt.Println()
	}

	if result, err := scanner.Scan([]byte("this one has only one secret.")); err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%+v\n", result.Matches)
		fmt.Println("processed:", string(result.Event))
		fmt.Println("mutated:", result.Mutated)
		fmt.Println()
	}

	if result, err := scanner.Scan([]byte("this one has an apikey <--- this should be a hash.")); err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%+v\n", result.Matches)
		fmt.Println("processed:", string(result.Event))
		fmt.Println("mutated:", result.Mutated)
		fmt.Println()
	}

	scanner.Delete()
}
