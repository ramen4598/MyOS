#include "common.h"

void putchar(char ch);

void printf(const char *fmt, ...) {
	va_list vargs;
	va_start(vargs, fmt);

	while (*fmt) {
		if (*fmt == '%') {
			fmt++; // Skip '%'
			switch (*fmt) { 	// Read the next character
				case '\0': 	// '%' at the end of the format string
					putchar('%');
					goto end;
				case '%':	// print '%'
					putchar('%');
					break;
				case 's': {	// Print a NULL-terminated string
					const char *s = va_arg(vargs, const char *);
					while(*s) {	// if not NULL
						putchar(*s);
						s++;
					}
					break;
				}
				case 'd': {	// Print an integer in decimal
					int value = va_arg(vargs, int);
					if (value < 0) {
						putchar('-');
						value = -value;
					}

					int divisor = 1;	// 자릿수
					while(value / divisor > 9)
						divisor *= 10;

					while (divisor > 0) {
						putchar('0' + value / divisor);	// int -> char
						value %= divisor;
						divisor /= 10;
					}

					break;
				}
				case 'x': {	// Print an integer in hexadecimal.
					int value = va_arg(vargs, int);
					for (int i = 7; i >= 0; i--) {	// 앞에서부터 4bit 씩 처리
						int nibble = (value >> (i*4)) & 0xf;	// 4bit씩 추출
						putchar("0123456789abcdef"[nibble]);
					}
				}
			}
		} else {
			putchar(*fmt);
		}

		fmt++;
	}

end:
	va_end(vargs);
}
