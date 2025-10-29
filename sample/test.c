#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    puts("Hello world");
	printf("I'm %d \n",getpid());
	char *p[0x10];
	char *q[0x10];
	for (int i=0;i<0x6;i++) {
		p[i]=malloc(0x20);
	}
	for (int i=0;i<0x5;i++) {
		free(p[i]);
	}
	for (int i=0;i<0x6;i++) {
		q[i]=malloc(0x50);
	}
	for (int i=0;i<0x5;i++) {
		free(q[i]);
	}
	char buf[0x20];
	fgets(buf,0x20,stdin);
	printf("hello %s!\n",buf);
	exit(0);
}
