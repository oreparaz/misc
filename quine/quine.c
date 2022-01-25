char c[] = ""
 "// little quine, 80s style. 2022-01-10\n\n#include <stdio.h>"
 "\n\nint main(void) {\n    char b[1000];\n    for (char *p = "
 "c, *q = b; *p; p++) {\n        if (!(q-b & 63)) { *q++='\\\""
 "';\n          *q++='\\n'; *q++=' '; *q++='\\\"'; }\n        "
 "if (*p=='\\\"' || *p=='\\\\') *q++='\\\\';\n        if (*p=="
 "'\\n') { *q++='\\\\'; *q++='n'; }\n        else *q++=*p;\n  "
 "  }\n    printf(\"char c[] = \\\"%s\\\";\\n\\n\", b);\n    p"
 "rintf(\"%s\\n\", c);\n}";

// little quine, 80s style. 2022-01-10

#include <stdio.h>

int main(void) {
    char b[1000];
    for (char *p = c, *q = b; *p; p++) {
        if (!(q-b & 63)) { *q++='\"';
          *q++='\n'; *q++=' '; *q++='\"'; }
        if (*p=='\"' || *p=='\\') *q++='\\';
        if (*p=='\n') { *q++='\\'; *q++='n'; }
        else *q++=*p;
    }
    printf("char c[] = \"%s\";\n\n", b);
    printf("%s\n", c);
}
