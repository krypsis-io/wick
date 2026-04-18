# VHS demo tape for Wick
# https://github.com/charmbracelet/vhs

Output demo.gif

Require wick

Set Shell "bash"
Set FontSize 16
Set Width 1300
Set Height 600
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

# Pre-create demo files off-screen
Hide
Ctrl+C
Type `printf '%s\n' '2026-04-17T08:12:01Z level=info msg="request received" user=dschrute@dundermifflin.com src=10.251.38.19' '2026-04-17T08:12:01Z level=info msg="session started" user=mscott@dundermifflin.com src=172.16.4.200' '2026-04-17T08:12:02Z level=error msg="upstream timeout" dst=10.251.38.22:5432' > /tmp/wick-demo.log`
Enter
Sleep 1s
Type `printf '%s\n' 'GITHUB_TOKEN=ghp_ABCDEFghijklmnopQRSTUVwxyz0123456789' 'AWS_ACCESS_KEY_ID=AKIAZ5GMHYJKLMNOPQRS' 'STRIPE_SECRET_KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc' > /tmp/wick-demo.env`
Enter
Sleep 1s
Ctrl+L
Show

Type "# App logs with PII"
Enter
Sleep 1s

Type "cat /tmp/wick-demo.log"
Enter
Sleep 3s

Type "cat /tmp/wick-demo.log | wick --summary"
Enter
Sleep 4s

Type "# .env file with secrets"
Enter
Sleep 1s

Type "cat /tmp/wick-demo.env"
Enter
Sleep 3s

Type "cat /tmp/wick-demo.env | wick --summary"
Enter
Sleep 5s
