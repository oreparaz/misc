# Some quines

`quine.c`: an easy quine in C

## Build

```
gcc -std=c11 -pedantic -Wall -Werror -Wextra quine.c -o quine
./quine > quine2.c
shasum -a 256 *c
f3beb057bd02ac55eb321b8476982f0481d3a71c7e002658ac8952c07033fcaa  quine.c
f3beb057bd02ac55eb321b8476982f0481d3a71c7e002658ac8952c07033fcaa  quine2.c
```
