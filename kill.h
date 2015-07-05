#include <regex.h>

regex_t excluded_cmdlines_regexp;

void handle_oom(DIR *, int, int, int);
