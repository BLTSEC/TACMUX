# TACMUX command map

Every command, grouped by job. `tm COMMAND --help` shows exact forms, accepted
words, and examples, and never writes to SITREP. The
[operator guide](USAGE.md) explains each one.

```text
Record      tm log [OUTCOME] [-c] [-l] [-i IMAGE] TEXT  'Title :: details'; outcomes:
                                                     info success partial failed
            tm fail TEXT · tm done [-s] TEXT         shorthands for failed / success
            tm access [LEVEL] [AS] [HOW…]            access gained, one undoable step
            tm proof|flag [user|root] [VALUE] [PATH] flag/proof with a screenshot
            tm creds [view [ID] | add | confirm]     credentials and where they work
            tm ports add [TARGET] [FILE]             Nmap output: FILE, stdin, or a picker
            tm todo | tm cleanup [add|done|reopen]   checklists in SITREP
            tm undo [--yes]
Inspect     tm status [TARGET|ops] · tm history [TARGET] [--outcome O] · tm ports [TARGET]
            tm sitrep [SECTION|TARGET] · tm log edit [EVENT_ID]
            tm evidence [TARGET]                     everything recorded, opens any
Targets     tm init [NAME] [ENDPOINT] · tm target [add|update|export|rename|delete|list]
            tm notes [FOLDER|none|move]              notes folder for new engagements
            tm discover [nmap|hosts|netexec]         reviewed host import
Sessions    tm (palette in a session, switcher elsewhere) · tm menu · tm switch
            tm snap [TARGET|ops] · tm close [TARGET|--engagement] · tm stop [TARGET|ops]
Maintain    tm sitrep sync · tm health · tm help [COMMAND] · tm version
            eval "$(tacmux shell-init zsh)"          command journal (installer adds it)
```

## Keys

After your tmux prefix: `M` palette · `E` switcher · `T` toggle pane
logging · `S` save an exact pane capture. An optional status-line badge,
`[ORCHID · user · LOG]`, makes an unrecorded `none` stand out
([three lines of tmux config](KEYBINDINGS.md#status-line-optional)).
