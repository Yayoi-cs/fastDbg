#include<stdio.h>
#include<unistd.h>

void hi2(void) {
	puts("hi2");
}

void hi1(void) {
	puts("hi1");
	hi2();
}

int main(void) {
	char buf[0x20];
	fgets(buf,sizeof(buf),stdin);
	puts("main");
	hi1();
}
