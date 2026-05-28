#include <sys/ioctl.h>
#include <sys/wait.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>


enum {
 KEY_ENTER = 1,
 KEY_HOME,
 KEY_END,
 KEY_TERM,
 KEY_UP,
 KEY_RIGHT,
 KEY_DOWN,
 KEY_LEFT,
};

struct field {
 size_t so;
 size_t eo;
 size_t lo;
};

static regex_t reg;

static char **yankargv;

static struct {
 size_t nmemb;
 size_t size;
 struct field *v;
} f;

static struct {
 size_t size;
 size_t nmemb;
 char *v;
} in;

static struct {
 int rfd;
 int wfd;
 int ca;
 struct termios attr;
} tty;

static void
input(void)
{
 int n;

 in.size = 8192;
 if ((in.v = malloc(in.size)) == ((void*)0))
  err(1, ((void*)0));

 while ((n = read(0, in.v + in.nmemb, in.size - in.nmemb)) != 0) {
  if (n == -1)
   err(1, "read");
  in.nmemb += n;

  if (in.nmemb < in.size)
   continue;
  in.size *= 2;
  if ((in.v = realloc(in.v, in.size)) == ((void*)0))
   err(1, ((void*)0));
 }
 memset(in.v + in.nmemb, 0, in.size - in.nmemb);
}





static char *
strtopat(const char *s)
{
 const char *fmt = "[^%s\f\n\r\t]+";
 char *pat;
 size_t len;
 int n;

 len = strlen(s) + strlen(fmt) + 1;
 if ((pat = malloc(len)) == ((void*)0))
  err(1, ((void*)0));
 n = snprintf(pat, len, fmt, s);
 if (n == -1 || n >= (ssize_t)len)
  errx(1, "pattern too long");

 return pat;
}






static int
fcmp(const struct field *f1, const struct field *f2)
{
 size_t e1, e2, s1, s2;

 s1 = f1->so - f1->lo, e1 = f1->eo - f1->lo;
 s2 = f2->so - f2->lo, e2 = f2->eo - f2->lo;

 return ((s1) > (s2) ? (s1) : (s2)) <= ((e1) < (e2) ? (e1) : (e2)) ? 0 : (e1 < s2 ? 1 : -1);
}

static ssize_t
xwrite(int fd, const char *s, size_t nmemb)
{
 size_t n;

 n = nmemb;
 do {
  ssize_t r;

  r = write(fd, s, n);
  if (r == -1)
   return r;
  n -= r;
  s += r;
 } while (n);

 return nmemb;
}

static void
yank(const char *s, size_t nmemb)
{
 int fd[2];
 int status;
 pid_t pid;

 if (!isatty(1)) {
  if (xwrite(1, s, nmemb) == -1)
   err(1, "write");
  exit(0);
 }

 if (pipe(fd) == -1)
  err(1, "pipe");
 if (dup2(fd[0], 0) == -1)
  err(1, "dup2");
 if (close(fd[0]) == -1)
  err(1, "close");
 if (xwrite(fd[1], s, nmemb) == -1)
  err(1, "write");
 if (close(fd[1]) == -1)
  err(1, "close");
 pid = fork();
 switch (pid) {
 case -1:
  err(1, "fork");

 case 0:
  execvp(yankargv[0], yankargv);
  err(126 + ((*__errno_location ()) == 2), "%s", yankargv[0]);

 default:
  if (waitpid(pid, &status, 0) == -1)
   err(1, "waitpid");
  if ((((signed char) (((status) & 0x7f) + 1) >> 1) > 0))
   exit(128 + ((status) & 0x7f));
  if ((((status) & 0x7f) == 0))
   exit((((status) & 0xff00) >> 8));
 }
}

static void
twrite(const char *s, size_t nmemb)
{
 if (xwrite(tty.wfd, s, nmemb) == -1)
  err(1, "write");
}

static void
tputs(const char *s)
{
 size_t n;

 n = strlen(s);
 twrite(s, n);
}

static void
tsetup(void)
{
 struct termios attr;
 struct winsize ws;
 regmatch_t r;
 char *e, *s;
 size_t m, n;
 unsigned int i, j;

 if ((tty.rfd = open("/dev/tty", 00)) == -1)
  err(1, "/dev/tty");
 if ((tty.wfd = open("/dev/tty", 01)) == -1)
  err(1, "/dev/tty");

 if (ioctl(tty.rfd, 0x5413, &ws) == -1)
  err(1, "TIOCGWINSZ");

 f.size = 32;
 if ((f.v = malloc(f.size*sizeof(struct field))) == ((void*)0))
  err(1, ((void*)0));
 m = n = ((ws.ws_col*ws.ws_row) < ((ssize_t)in.nmemb) ? (ws.ws_col*ws.ws_row) : ((ssize_t)in.nmemb));
 s = e = in.v;
 while (m && !regexec(&reg, e, 1, &r, 0) && r.rm_eo - r.rm_so) {
  f.v[f.nmemb].so = f.v[f.nmemb].eo = e - s;
  f.v[f.nmemb].so += r.rm_so;
  f.v[f.nmemb].eo += ((((r.rm_eo) < ((ssize_t)m) ? (r.rm_eo) : ((ssize_t)m)) - 1) > (0) ? (((r.rm_eo) < ((ssize_t)m) ? (r.rm_eo) : ((ssize_t)m)) - 1) : (0));
  e += r.rm_eo;
  m -= ((r.rm_eo) < ((ssize_t)m) ? (r.rm_eo) : ((ssize_t)m));

  if (++f.nmemb < f.size)
   continue;
  f.size *= 2;
  if ((f.v = realloc(f.v, f.size*sizeof(struct field))) == ((void*)0))
   err(1, ((void*)0));
 }

 for (i = j = 0, s = e = in.v; n && i < ws.ws_row; i++) {
  size_t w;

  if (s == e && !(e = memchr(s + 1, '\n', n)))
   e = in.v + in.nmemb;

  w = ((e - s) < (ws.ws_col) ? (e - s) : (ws.ws_col));
  for (; j < f.nmemb && f.v[j].so < (size_t)(s - in.v + w); j++)
   f.v[j].lo = s - in.v;
  s += w;
  n -= w;
 }
 f.nmemb = ((f.nmemb) < (j) ? (f.nmemb) : (j));

 if (n > 0 && f.nmemb > 0 &&
     f.v[f.nmemb - 1].eo - f.v[f.nmemb - 1].lo >= ws.ws_col)
  f.v[f.nmemb - 1].eo = f.v[f.nmemb - 1].lo + ws.ws_col - 1;

 f.v[f.nmemb].lo = ((s - in.v - 1) > (0) ? (s - in.v - 1) : (0));

 if (tcgetattr(tty.rfd, &tty.attr) == -1)
  err(1, "tcgetattr");
 attr = tty.attr;
 attr.c_iflag |= 0000400;
 attr.c_lflag &= ~(0000002|0000010|0000001);
 if (tcsetattr(tty.rfd, 0, &attr) == -1)
  err(1, "tcsetattr");

 if (tty.ca)
  tputs("\033[?1049h");
 tputs("\033[?25l");

 for (j = 0; j < i; j++)
  tputs("\n");
 for (j = 0; j < i; j++)
  tputs("\033M");
 tputs("\0337");
}

static void
tend(void)
{
 tputs("\0338");
 tputs("\033[J");
 tputs("\033[?25h");
 if (tty.ca)
  tputs("\033[?1049l");
 tcsetattr(tty.rfd, 0, &tty.attr);
 close(tty.rfd);
 close(tty.wfd);
}

static int
tgetc(void)
{
 static struct {
  const char *s;
  int c;
 } keys[] = {
  { "\n", KEY_ENTER },
  { "\001", KEY_HOME },
  { "\003", KEY_TERM },
  { "\004", KEY_TERM },
  { "\005", KEY_END },
  { "\016", KEY_RIGHT },
  { "\020", KEY_LEFT },
  { "G", KEY_END },
  { "g", KEY_HOME },
  { "h", KEY_LEFT },
  { "j", KEY_DOWN },
  { "k", KEY_UP },
  { "l", KEY_RIGHT },
  { "\033[A", KEY_UP },
  { "\033[C", KEY_RIGHT },
  { "\033[B", KEY_DOWN },
  { "\033[D", KEY_LEFT },
  { ((void*)0), 0 },
 };
 char buf[4];
 ssize_t n;
 int i;

 n = read(tty.rfd, buf, sizeof(buf) - 1);
 if (n == -1)
  err(1, "read");
 if (n == 0)
  return KEY_TERM;
 buf[n] = '\0';

 for (i = 0; keys[i].s != ((void*)0); i++) {
  if (strncmp(keys[i].s, buf, strlen(keys[i].s)) == 0)
   return keys[i].c;
 }

 return 0;
}

static const struct field *
tmain(void)
{
 size_t n;
 int i, j;

 i = j = 0;
 n = f.v[f.nmemb].lo;
 for (;;) {
  int c;

  tputs("\0338");
  if (f.nmemb > 0) {
   twrite(in.v, f.v[i].so);
   tputs("\033[7m");
   twrite(in.v + f.v[i].so, f.v[i].eo - f.v[i].so + 1);
   tputs("\033[0m");
   twrite(in.v + f.v[i].eo + 1, n - f.v[i].eo);
  } else {
   twrite(in.v, n);
  }

  c = tgetc();
  switch (c) {
  case KEY_ENTER:
   if (f.nmemb > 0)
    return &f.v[i];
   break;
  case KEY_TERM:
   return ((void*)0);
  case KEY_HOME:
   j = 0;
   break;
  case KEY_RIGHT:
   j = i + 1;
   break;
  case KEY_END:
   j = f.nmemb - 1;
   break;
  case KEY_LEFT:
   j = i - 1;
   break;
  case KEY_DOWN:
  case KEY_UP:
   if (c == KEY_DOWN) {
    j = i;
    while (j < (ssize_t)f.nmemb &&
        f.v[i].lo == f.v[j].lo)
     j++;
    if (j == (ssize_t)f.nmemb)
     break;
   } else {
    int k = i;
    while (k && f.v[i].lo == f.v[k].lo)
     k--;
    j = k;
    while (j && f.v[j - 1].lo == f.v[k].lo)
     j--;
   }
   for (; fcmp(&f.v[i], &f.v[j]) < 0 &&
       f.v[j].lo == f.v[j + 1].lo; j++)
    continue;
   break;
  }
  if (j >= 0 && j < (ssize_t)f.nmemb)
   i = j;
 }
}

static void
usage(void)
{
 fprintf(stderr, "usage: yank [-1ilxv] [-d delim] [-g pattern] "
     "[-- command [args]]\n");
 exit(2);
}

int
main(int argc, char *argv[])
{
 const struct field *field;
 char *pat;
 int one = 0;
 int rflags = 1;
 int c, i;

 setlocale(0, "");






 pat = strtopat(" ");
 while ((c = getopt(argc, argv, "1ilvxd:g:")) != -1) {
  switch (c) {
  case '1':
   one = 1;
   break;
  case 'd':
   free(pat);
   pat = strtopat(optarg);
   break;
  case 'g':
   free(pat);
   if ((pat = strdup(optarg)) == ((void*)0))
    err(1, ((void*)0));
   rflags |= (1 << 2);
   break;
  case 'i':
   rflags |= (1 << 1);
   break;
  case 'l':
   free(pat);
   pat = strtopat("");
   break;
  case 'v':
   puts("yank " VERSION);
   exit(0);
  case 'x':
   tty.ca = 1;
   break;
  default:
   usage();
  }
 }
 argc -= optind;
 argv += optind;

 if (regcomp(&reg, pat, rflags) != 0)
  errx(1, "invalid regular expression");


 if ((yankargv = calloc(argc + 2, sizeof(char *))) == ((void*)0))
  err(1, ((void*)0));
 yankargv[0] = YANKCMD;
 for (i = 0; i < argc; i++)
  yankargv[i] = argv[i];

 input();
 tsetup();
 if (one && f.nmemb == 1)
  field = &f.v[0];
 else
  field = tmain();
 tend();
 if (field == ((void*)0))
  return 1;
 yank(in.v + field->so, field->eo - field->so + 1);

 return 0;
}
