package findruction

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// MemReader is the small interface the TUI needs from the debugger backend
// to fetch live bytes for runtime-mode matches.
type MemReader interface {
	ReadMem(addr uint64, n int) []byte
}

// RunTUI presents `groups` in a 3-pane interactive layout:
//
//	left   — list of groups (libraries or executable regions)
//	center — addresses of matches in the currently-selected group
//	right  — disassembly of the currently-selected match
//
// Tab cycles focus through the panes; arrow keys (or j/k) navigate the
// focused list; PgUp/PgDn scroll the disasm pane; q or Esc quits.
//
// `reader` is consulted only when a group has runtime-only matches (no
// FileOffset) — i.e. the address-bounded mode. Otherwise the bytes for
// disassembly come straight from the ELF file at FileOffset, which is fast
// and works even after the debuggee has exited.
func RunTUI(groups []Group, pattern []byte, reader MemReader) error {
	app := tview.NewApplication()

	libsList := tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true)
	libsList.SetBorder(true).SetTitle(fmt.Sprintf(" libraries (%d) ", len(groups)))

	matchesList := tview.NewList().
		ShowSecondaryText(false).
		SetHighlightFullLine(true)
	matchesList.SetBorder(true).SetTitle(" matches ")

	disasmView := tview.NewTextView().
		SetDynamicColors(true).
		SetWrap(false).
		SetScrollable(true)
	disasmView.SetBorder(true).SetTitle(" disassembly ")

	header := tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	patternHex := strings.Builder{}
	for _, b := range pattern {
		fmt.Fprintf(&patternHex, "%02x", b)
	}
	totalMatches := 0
	groupsWithMatches := 0
	for _, g := range groups {
		totalMatches += len(g.Matches)
		if len(g.Matches) > 0 {
			groupsWithMatches++
		}
	}
	header.SetText(fmt.Sprintf(
		" [green::b]findruction[-:-:-]  pattern=[cyan]%s[-]  [yellow]%d[-] match(es) across [yellow]%d[-]/[yellow]%d[-] groups",
		patternHex.String(), totalMatches, groupsWithMatches, len(groups)))

	footer := tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	footer.SetText(" [yellow]Tab[-] focus  [yellow]↑↓/jk[-] select  [yellow]PgUp/PgDn[-] scroll disasm  [yellow]q[-] quit ")

	// Populate left pane. Empty groups appear dimmed; selecting them just
	// shows an empty matches pane.
	currentGroup := -1
	repopulateMatches := func(gi int) {
		matchesList.Clear()
		if gi < 0 || gi >= len(groups) {
			disasmView.Clear()
			return
		}
		g := groups[gi]
		matchesList.SetTitle(fmt.Sprintf(" matches (%d) ", len(g.Matches)))
		if g.Err != nil {
			matchesList.AddItem(fmt.Sprintf("[red]<error: %v>[-]", g.Err), "", 0, nil)
			disasmView.SetText(fmt.Sprintf("[red]%v[-]", g.Err))
			return
		}
		for mi, m := range g.Matches {
			abs := m.Vaddr
			if g.LoadBase != 0 {
				abs = g.LoadBase + m.Vaddr
			}
			label := fmt.Sprintf("#%-3d 0x%016x", mi+1, abs)
			matchesList.AddItem(label, "", 0, nil)
		}
		if len(g.Matches) == 0 {
			disasmView.Clear()
		}
	}

	renderDisasm := func(gi, mi int) {
		disasmView.Clear()
		if gi < 0 || gi >= len(groups) {
			return
		}
		g := groups[gi]
		if mi < 0 || mi >= len(g.Matches) {
			return
		}
		m := g.Matches[mi]
		abs := m.Vaddr
		if g.LoadBase != 0 {
			abs = g.LoadBase + m.Vaddr
		}

		var sb strings.Builder
		fmt.Fprintf(&sb, " [yellow]%s[-]\n", g.Label)
		fmt.Fprintf(&sb, " match #%d/%d  vaddr=[cyan]0x%016x[-]", mi+1, len(g.Matches), abs)
		if m.FileOffset != 0 {
			fmt.Fprintf(&sb, "  file_off=[blue]0x%x[-]", m.FileOffset)
		}
		fmt.Fprintln(&sb)
		fmt.Fprintln(&sb)

		var bytes []byte
		// Prefer the file when we have a FileOffset (covers ELF-mode and
		// works after the process exits); fall back to live memory for the
		// address-bounded mode where FileOffset is 0.
		if g.Path != "" && m.FileOffset != 0 {
			bytes = fileBytesAt(g.Path, m.FileOffset, 64*16)
		} else if reader != nil {
			bytes = reader.ReadMem(abs, 64*16)
		}

		insns := disassembleAt(bytes, abs, 64)
		if len(insns) == 0 {
			fmt.Fprintf(&sb, " [yellow]<unable to disassemble at 0x%016x>[-]\n", abs)
		}
		for _, in := range insns {
			if in.OpStr != "" {
				fmt.Fprintf(&sb, " [cyan]0x%016x[-]: [blue]%s[-] %s\n", in.Address, in.Mnemonic, in.OpStr)
			} else {
				fmt.Fprintf(&sb, " [cyan]0x%016x[-]: [blue]%s[-]\n", in.Address, in.Mnemonic)
			}
		}
		disasmView.SetText(sb.String())
		disasmView.ScrollToBeginning()
	}

	libsList.SetChangedFunc(func(idx int, _, _ string, _ rune) {
		currentGroup = idx
		repopulateMatches(idx)
		if idx >= 0 && idx < len(groups) && len(groups[idx].Matches) > 0 {
			matchesList.SetCurrentItem(0)
			renderDisasm(idx, 0)
		} else {
			disasmView.Clear()
		}
	})
	matchesList.SetChangedFunc(func(idx int, _, _ string, _ rune) {
		renderDisasm(currentGroup, idx)
	})

	// Initial fill of the left pane. Pre-select the first group that has
	// matches so the user lands on something useful.
	firstWithMatches := -1
	for gi, g := range groups {
		base := g.Label
		if g.Path != "" {
			base = filepath.Base(g.Path)
			if base == "" || base == "." {
				base = g.Label
			}
		}
		count := len(g.Matches)
		var label string
		switch {
		case g.Err != nil:
			label = fmt.Sprintf("[red]%s (err)[-]", base)
		case count == 0:
			label = fmt.Sprintf("[gray]%s (0)[-]", base)
		default:
			label = fmt.Sprintf("%s ([yellow]%d[-])", base, count)
		}
		libsList.AddItem(label, "", 0, nil)
		if firstWithMatches < 0 && count > 0 {
			firstWithMatches = gi
		}
	}
	if firstWithMatches < 0 {
		firstWithMatches = 0
	}
	libsList.SetCurrentItem(firstWithMatches)

	// Layout: 3-column body + header + footer.
	body := tview.NewFlex().SetDirection(tview.FlexColumn).
		AddItem(libsList, 0, 22, true).
		AddItem(matchesList, 0, 28, false).
		AddItem(disasmView, 0, 50, false)

	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(header, 1, 0, false).
		AddItem(body, 0, 1, true).
		AddItem(footer, 1, 0, false)

	// Focus management: cycle through libs → matches → disasm. Highlight
	// the focused border by tinting its title.
	focusOrder := []tview.Primitive{libsList, matchesList, disasmView}
	highlightFocus := func() {
		titles := []struct {
			p     tview.Primitive
			title string
		}{
			{libsList, fmt.Sprintf(" libraries (%d) ", len(groups))},
			{matchesList, matchesList.GetTitle()},
			{disasmView, " disassembly "},
		}
		current := app.GetFocus()
		for _, t := range titles {
			b, ok := t.p.(*tview.Box)
			_ = b
			_ = ok
			// Box methods are inherited; use type-specific setters below.
		}
		_ = current
		// Simpler approach: just set border colors via type assertion.
		setBorderColor(libsList, libsList == current)
		setBorderColor(matchesList, matchesList == current)
		setBorderColor(disasmView, disasmView == current)
	}
	cycleFocus := func(forward bool) {
		current := app.GetFocus()
		idx := 0
		for i, p := range focusOrder {
			if p == current {
				idx = i
				break
			}
		}
		if forward {
			idx = (idx + 1) % len(focusOrder)
		} else {
			idx = (idx - 1 + len(focusOrder)) % len(focusOrder)
		}
		app.SetFocus(focusOrder[idx])
		highlightFocus()
	}

	app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Key() {
		case tcell.KeyEscape, tcell.KeyCtrlC:
			app.Stop()
			return nil
		case tcell.KeyTab:
			cycleFocus(true)
			return nil
		case tcell.KeyBacktab:
			cycleFocus(false)
			return nil
		}
		switch event.Rune() {
		case 'q':
			app.Stop()
			return nil
		}
		return event
	})

	// Initial selection callbacks fire only on change, so trigger one
	// manually so the user starts with disasm shown.
	repopulateMatches(firstWithMatches)
	if firstWithMatches >= 0 && firstWithMatches < len(groups) && len(groups[firstWithMatches].Matches) > 0 {
		currentGroup = firstWithMatches
		renderDisasm(firstWithMatches, 0)
	}
	highlightFocus()

	return app.SetRoot(root, true).SetFocus(libsList).Run()
}

// setBorderColor tints a primitive's border yellow when focused, default otherwise.
// We type-switch because tview's Box method set isn't exported on the interface.
func setBorderColor(p tview.Primitive, focused bool) {
	color := tcell.ColorWhite
	if focused {
		color = tcell.ColorYellow
	}
	switch v := p.(type) {
	case *tview.List:
		v.SetBorderColor(color)
	case *tview.TextView:
		v.SetBorderColor(color)
	}
}
