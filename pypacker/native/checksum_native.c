/*
# Compilation examples
gcc -fPIC -c checksum_native.c
gcc -shared -o checksum_native.so checksum_native.o
*/
#include <stdint.h>
//#include <Python.h>
#include <python3.10/Python.h>

// TODO remove
//#include <string.h>
//#include <stdio.h>


/*
WARNING: this code doesn't do any sanity checks!
Make sure buf_len matches the amount of bytes pointed to by buf.
*/
uint32_t in_chksum(uint8_t* buf, uint32_t buf_len) {
	uint32_t chksum = 0;
	uint32_t buf_len_even = buf_len & 0xFFFFFFFE;
	//printf("buf_len = %d, buf_len_even = %d\n", buf_len, buf_len_even);

	for (uint32_t idx=0; idx != buf_len_even; idx += 2) {
		//printf("%d\n", idx);
		// Assume BE input
		// Store as LE
		chksum += (buf[idx] + (buf[idx + 1] << 8));
		//printf("chksum step %d: %#010x\n", idx, chksum);
	}

	if (buf_len != buf_len_even)
		chksum += buf[buf_len_even];

	//printf("chksum before finalization: %#010x\n", chksum);
	// Add carry
	chksum = (chksum >> 16) + (chksum & 0xFFFF);
	chksum += (chksum >> 16);
	//printf("chksum after carry: %#010x\n", chksum);
	// Return complement of sums
	chksum = (~chksum) & 0xFFFF;
	//printf("chksum after complement 1: %#010x\n", chksum);
	chksum = ((chksum & 0x00FF) << 8) + ((chksum & 0xFF00) >> 8);
	//printf("chksum after complement 2: %#010x\n", chksum);
	return chksum;
}

/*
Example calls
*/
int main() {
	//char* buf = "\x00\x01\x00\x01\x04"; // 0x0000fbfd
	//uint32_t buf_len = 5;
	//char* buf = "\x00\x01\x00\x01\x00\x01"; // 0x0000fffc
	//uint32_t buf_len = 6;
	//char* buf = "\x0F\xFF\xFF\xFF\xFF\xFF"; // 0X0000F000
	//uint32_t buf_len = 6;
	char* buf = "\xFF\xFF\xFF\xFF\xFF\xFF"; // 0X00000000
	uint32_t buf_len = 6;
	uint32_t chksum = in_chksum(buf, buf_len);

	printf("Checksum: %d\n", chksum);
}
/*
PyMODINIT_FUNC PyInit_checksum_native(void) {
    Py_Initialize();
    return PyModule_Create(&functio_def);
}
*/
