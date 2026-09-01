# Reproducible tour of the public synthetic TACMUX fixture.
Require tacmux
Require python3
Require tmux
Require zsh

Set Shell "zsh"
Set FontFamily "MesloLGS Nerd Font Mono"
Set FontSize 17
Set Width 1200
Set Height 750
Set Padding 12
Set Framerate 12
Set Theme {"background":"#060b13","foreground":"#d7e2f0","cursor":"#24d6c8","black":"#111827","red":"#ff5c6c","green":"#43d17b","yellow":"#f5c451","blue":"#55a7ff","magenta":"#c084fc","cyan":"#24d6c8","white":"#e8eef7","brightBlack":"#64748b","brightRed":"#ff7a87","brightGreen":"#65e495","brightYellow":"#ffdb7a","brightBlue":"#7dbbff","brightMagenta":"#d8a8ff","brightCyan":"#5ce6dc","brightWhite":"#ffffff"}
Set WindowBar Colorful
Set BorderRadius 8
Set TypingSpeed 35ms

Output assets/.tacmux-v2-demo.raw.mp4

Hide
Type@1ms "source ~/.zshrc >/dev/null 2>&1 || true; exec zsh -f"
Enter
Wait /%/
Type@1ms "export PS1='tacmux-demo ❯ '"
Enter
Wait /tacmux-demo ❯/
Type@1ms "python3 scripts/demo/setup-tacmux-demo.py /tmp/tacmux-vhs-demo"
Enter
Wait /tacmux-demo ❯/
Type@1ms "source /tmp/tacmux-vhs-demo/demo.env; clear"
Enter
Wait /tacmux-demo ❯/
Show

Type@45ms "tacmux"
Enter
Wait /Northstar Example/
Sleep 3s

Type "2"
Sleep 2s

Type "3"
Sleep 2s

Type "4"
Sleep 2s

Type "5"
Sleep 2s

Type "1"
Sleep 2s

Type "a"
Sleep 3s
