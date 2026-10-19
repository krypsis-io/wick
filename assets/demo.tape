# VHS tape for assets/demo.gif: https://github.com/charmbracelet/vhs
#
# Needs a cluster with the objects in assets/demo.yaml. See that file.

Output assets/demo.gif

Require kubectl
Require wick

Set Shell "bash"
Set FontSize 16
Set Width 1040
Set Height 400
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Hide
Type "export PS1='$ '"
Enter
Ctrl+L
Show

Type "kubectl -n demo logs deploy/checkout"
Sleep 300ms
Enter
Sleep 3s
Enter

Type "kubectl -n demo logs deploy/checkout | wick"
Sleep 300ms
Enter
Sleep 5s

Hide
Ctrl+L
Show

Type "kubectl -n demo get secret checkout-db -o yaml | wick --summary"
Sleep 300ms
Enter
Sleep 6s
