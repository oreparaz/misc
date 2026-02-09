/* run as
   cc -o breathe breathe.c && ./breathe -duration 5 -width 8 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CLEAR_SCREEN "\033[2J"
#define MOVE_CURSOR  "\033[0;0H"
#define COLOR_CYAN   "\033[36m"
#define COLOR_RESET  "\033[0m"

static void draw_bar(int pos, int width)
{
	printf("%s%s[", MOVE_CURSOR, COLOR_CYAN);
	for (int i = 0; i < pos; i++)
		putchar(' ');
	printf("●");  /* UTF-8 bullet */
	for (int i = 0; i < width - pos; i++)
		putchar(' ');
	printf("%s%s]\n", COLOR_RESET, COLOR_CYAN);
}

static void breathe_cycle(int width, int duration_sec)
{
	int delay_us = duration_sec * 1000000 / width;

	/* inhale */
	for (int i = 0; i < width; i++) {
		draw_bar(i, width - 1);
		usleep(delay_us);
	}
	/* exhale */
	for (int i = width - 2; i > 0; i--) {
		draw_bar(i, width - 1);
		usleep(delay_us);
	}
}

int main(int argc, char *argv[])
{
	int width = 11;
	int duration = 8;

	for (int i = 1; i < argc - 1; i++) {
		if (strcmp(argv[i], "-width") == 0)
			width = atoi(argv[++i]);
		else if (strcmp(argv[i], "-duration") == 0)
			duration = atoi(argv[++i]);
	}

	printf("%s", CLEAR_SCREEN);
	for (;;)
		breathe_cycle(width, duration);

	return 0;
}
