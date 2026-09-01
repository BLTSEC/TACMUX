# Reproducible BLTSEC tour of the public synthetic TACMUX fixture.
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
Set Theme {"background":"#061012","foreground":"#dcecef","cursor":"#68e7f0","black":"#061012","red":"#f07178","green":"#99c794","yellow":"#fac863","blue":"#6699cc","magenta":"#c594c5","cyan":"#2fb5c8","white":"#dcecef","brightBlack":"#587276","brightRed":"#ff8b92","brightGreen":"#b8e0b4","brightYellow":"#ffe099","brightBlue":"#8ab4df","brightMagenta":"#ddb7dd","brightCyan":"#68e7f0","brightWhite":"#f4ffff"}
Set WindowBar Colorful
Set BorderRadius 8
Set TypingSpeed 35ms

Output assets/.tacmux-v2-demo.raw.mp4

Hide
Type@1ms "source ~/.zshrc >/dev/null 2>&1 || true; exec zsh -f"
Enter
Wait /%/
Type@1ms "export PS1='%F{51}BLTSEC%f %F{39}northstar%f ❯ '"
Enter
Wait /BLTSEC northstar ❯/
Type@1ms "python3 scripts/demo/setup-tacmux-demo.py /tmp/tacmux-vhs-demo"
Enter
Wait /BLTSEC northstar ❯/
Type@1ms "source /tmp/tacmux-vhs-demo/demo.env; clear"
Enter
Wait /BLTSEC northstar ❯/
Type@1ms "clear; print -P '%F{51}BLTSEC // TACMUX%f'; print -P '%F{39}NORTHSTAR EXAMPLE // SYNTHETIC ENGAGEMENT%f'"
Enter
Wait /BLTSEC northstar ❯/
Show
Sleep 4s

Type@45ms "tacmux"
Enter
Wait /Northstar Example/
Sleep 5s

Type "a"
Sleep 4s
Escape
Sleep 1s

Type "2"
Sleep 5s

Type "3"
Sleep 5s

Type "4"
Sleep 6s

Type "5"
Sleep 5s

Type "1"
Sleep 4s

Ctrl+P
Sleep 1s
Type@80ms "archive"
Sleep 5s
