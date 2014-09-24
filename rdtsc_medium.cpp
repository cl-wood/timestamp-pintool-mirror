// rdtsc_medium.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include <iostream>
using namespace std;

int main(int argc, char* argv[])
{
	unsigned int time1, time2 = 0;
	__asm
	{
		rdtsc
		mov time1, eax
		mov eax, 12000
myLoop:
		dec eax
		cmp eax, 0
		jne myLoop
		rdtsc
		mov time2, eax

	}
	cout << time2 - time1 << endl;
	if ((time2 - time1) > 9000 || time2 == time1)
	{
		MessageBox(NULL, (LPCWSTR)L"Suspicious slowdown", (LPCWSTR)L"OHNOES", NULL);
	}
	else
	{
		MessageBox(NULL, (LPCWSTR)L"Looks good, breh", (LPCWSTR)L"W00T", NULL);
	}	
}

