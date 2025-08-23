package main

import (
	"fmt"
	"github.com/manifoldco/promptui"
)

func (dbger *TypeDbg) Interactive() {
	dbger.LoadSymbolsFromELF()
	prev := ""

	templates := &promptui.PromptTemplates{
		Prompt:  "{{ . }}",
		Valid:   "{{ . }}",
		Invalid: "{{ . }}",
		Success: "{{ . }}",
	}
	for {
		var label string
		if !dbger.isStart {
			label = "[fastDbg]$ "
		} else {
			label = fmt.Sprintf("[%s%x%s]$ ", ColorCyan, dbger.rip, ColorReset)
		}

		prompt := promptui.Prompt{
			Label:     label,
			Templates: templates,
		}

		req, err := prompt.Run()
		if err != nil {
			if err == promptui.ErrInterrupt {
				break
			}
			continue
		}

		if req == "" {
			if prev == "" {
				continue
			}
			req = prev
		}

		if req == "q" || req == "exit" {
			break
		}
		prev = req
		err = dbger.cmdExec(req)

		if err != nil {
			LogError(err.Error())
		}
		dbger.Reload()
	}
}
