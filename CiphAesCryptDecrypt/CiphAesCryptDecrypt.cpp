#include <Windows.h>
#include <stdio.h>

// AES (Advanced Encryption Standard) による暗号化

// 仕様
// ADVANCED ENCRYPTION STANDARD (AES)
// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf

// Tests as below
// In ECB 
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ECB.pdf

// Figure 4.  Key-Block-Round Combinations.
// 
//           | Key Length | Block Size | Number of Rounds
//           | (Nk words) | (Nb words) | (Nr)
// ----------+------------+------------+----------------
// AES - 128 | 4          | 4          | 10
// ----------+------------+------------+----------------
// AES - 192 | 6          | 4          | 12
// ----------+------------+------------+----------------
// AES - 256 | 8          | 4          | 14
// ----------+------------+------------+----------------

typedef enum
{
	AES128 = 0,
	AES192,
	AES256
} AESBitLength;

AESBitLength CurrentAESBitLength;

BYTE KeyTable[3] = { 4, 6, 8 };
BYTE RoundTable[3] = { 10, 12, 14 };

// GFMultiplication 関数
// 与えられた引数に基づいて計算を行い、その結果を返す
// 引数をそれぞれ a, b とし、結果を c とする
// 以下の処理を b が 0 になるまで繰り返す。また c の初期値は 0 とする
// 1. b の最下位ビットが 1 の場合、c = a ^ c とする
// 2. a の最上位ビットが 1 の場合、a を 1 ビット左シフトした上で a = a ^ 0x1b とする
//    a の最上位ビットが 0 の場合、a を 1 ビット左シフトする
// 3. b を 1 ビット右シフトする
BYTE WINAPI GFMultiplication(BYTE a, BYTE b)
{
	BYTE aTemp, bTemp, c = 0;

	for (aTemp = a, bTemp = b; bTemp != 0; bTemp >>= 1)
	{
		if (bTemp & 1)
		{
			c ^= aTemp;
		}

		if (aTemp & 0x80)
		{
			aTemp <<= 1;
			aTemp ^= 0x1b;
		}
		else
		{
			aTemp <<= 1;
		}
	}

	return c;
}

// バイト値の1対1の非線形置換表
static const BYTE SBox[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// SubBytes 関数
// 置換テーブル (SBox) を使用して State の各バイトを置換する
VOID WINAPI SubBytes(BYTE* State) // 4 * Nb
{
	BYTE i;
	const BYTE Nb = 4;

	for (i = 0; i < 4 * Nb; i++)
	{
		State[i] = SBox[State[i]];
	}

	return;
}

// バイト値の1対1の非線形置換表
// SBox の逆バージョン
static const BYTE InvSBox[256] = {
	//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
	0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
	0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
	0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
	0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
	0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
	0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
	0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
	0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
	0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
	0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
	0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
	0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
	0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
	0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// InvSubBytes 関数
// 置換テーブル (InvSBox) を使用して State の各バイトを置換する
VOID WINAPI InvSubBytes(BYTE* State) // 4 * Nb
{
	BYTE i;
	const BYTE Nb = 4;

	for (i = 0; i < 4 * Nb; i++)
	{
		State[i] = InvSBox[State[i]];
	}

	return;
}

// ShiftRows 関数
// State の最後の 3 行のバイトが、循環的にシフトされる
// 最初の行 (r = 0) はシフトされない
//           S                        S'
// +----+----+----+----+    +----+----+----+----+
// |s0,0|s0,1|s0,2|s0,3|    |s0,0|s0,1|s0,2|s0,3|
// +----+----+----+----+    +----+----+----+----+
// |s1,0|s1,1|s1,2|s1,3|    |s1,1|s1,2|s1,3|s1,0|
// +----+----+----+----+ => +----+----+----+----+
// |s2,0|s2,1|s2,2|s2,3|    |s2,2|s2,3|s2,0|s2,1|
// +----+----+----+----+    +----+----+----+----+
// |s3,0|s3,1|s3,2|s3,3|    |s3,3|s3,0|s3,1|s3,2|
// +----+----+----+----+    +----+----+----+----+
VOID WINAPI ShiftRows(BYTE* State) // 4 * Nb
{
	BYTE btTemp;
	const BYTE Nb = 4;

	btTemp = State[1];
	State[1] = State[5];
	State[5] = State[9];
	State[9] = State[13];
	State[13] = btTemp;

	btTemp = State[2];
	State[2] = State[10];
	State[10] = btTemp;
	btTemp = State[6];
	State[6] = State[14];
	State[14] = btTemp;

	btTemp = State[3];
	State[3] = State[15];
	State[15] = State[11];
	State[11] = State[7];
	State[7] = btTemp;

	return;
}

// InvShiftRows 関数
// State の最後の 3 行のバイトが、循環的にシフトされる
// 最初の行 (r = 0) はシフトされない
//           S                        S'
// +----+----+----+----+    +----+----+----+----+
// |s0,0|s0,1|s0,2|s0,3|    |s0,0|s0,1|s0,2|s0,3|
// +----+----+----+----+    +----+----+----+----+
// |s1,0|s1,1|s1,2|s1,3|    |s1,3|s1,0|s1,1|s1,2|
// +----+----+----+----+ => +----+----+----+----+
// |s2,0|s2,1|s2,2|s2,3|    |s2,2|s2,3|s2,0|s2,1|
// +----+----+----+----+    +----+----+----+----+
// |s3,0|s3,1|s3,2|s3,3|    |s3,1|s3,2|s3,3|s3,0|
// +----+----+----+----+    +----+----+----+----+
VOID WINAPI InvShiftRows(BYTE* State) // 4 * Nb
{
	BYTE btTemp;

	btTemp = State[13];
	State[13] = State[9];
	State[9] = State[5];
	State[5] = State[1];
	State[1] = btTemp;

	btTemp = State[2];
	State[2] = State[10];
	State[10] = btTemp;
	btTemp = State[6];
	State[6] = State[14];
	State[14] = btTemp;

	btTemp = State[3];
	State[3] = State[7];
	State[7] = State[11];
	State[11] = State[15];
	State[15] = btTemp;

	return;
}

// MixColumns 関数
// State を列ごとに操作してそれぞれに処理を行う
// 次のような行列の計算を行う
// |S'0,c|   |02 03 01 01| |S0,c|
// |S'1,c| = |01 02 03 01| |S1,c|
// |S'2,c|   |01 01 02 03| |S2,c|
// |S'3,c|   |03 01 01 02| |S3,c|
VOID WINAPI MixColumns(BYTE* State) // 4 * Nb
{
	BYTE i, Temp[4];
	const BYTE Nb = 4;

	for (i = 0; i < Nb; i++)
	{
		Temp[0] = GFMultiplication(0x02, State[i * Nb]) ^ GFMultiplication(0x03, State[i * Nb + 1]) ^ State[i * Nb + 2] ^ State[i * Nb + 3];
		Temp[1] = State[i * Nb] ^ GFMultiplication(0x02, State[i * Nb + 1]) ^ GFMultiplication(0x03, State[i * Nb + 2]) ^ State[i * Nb + 3];
		Temp[2] = State[i * Nb] ^ State[i * Nb + 1] ^ GFMultiplication(0x02, State[i * Nb + 2]) ^ GFMultiplication(0x03, State[i * Nb + 3]);
		Temp[3] = GFMultiplication(0x03, State[i * Nb]) ^ State[i * Nb + 1] ^ State[i * Nb + 2] ^ GFMultiplication(0x02, State[i * Nb + 3]);
		memcpy(&State[i * Nb], Temp, sizeof(Temp));
	}

	return;
}

// InvMixColumns 関数
// State を列ごとに操作してそれぞれに処理を行う
// 次のような行列の計算を行う
// |S'0,c|   |0e 0b 0d 09| |S0,c|
// |S'1,c| = |09 0e 0b 0d| |S1,c|
// |S'2,c|   |0d 09 0e 0b| |S2,c|
// |S'3,c|   |0b 0d 09 0e| |S3,c|
VOID WINAPI InvMixColumns(BYTE* State) // 4 * Nb
{
	BYTE i, Temp[4];
	const BYTE Nb = 4;

	for (i = 0; i < Nb; i++)
	{
		Temp[0] = GFMultiplication(0x0e, State[i * Nb]) ^ GFMultiplication(0x0b, State[i * Nb + 1]) ^ GFMultiplication(0x0d, State[i * Nb + 2]) ^ GFMultiplication(0x09, State[i * Nb + 3]);
		Temp[1] = GFMultiplication(0x09, State[i * Nb]) ^ GFMultiplication(0x0e, State[i * Nb + 1]) ^ GFMultiplication(0x0b, State[i * Nb + 2]) ^ GFMultiplication(0x0d, State[i * Nb + 3]);
		Temp[2] = GFMultiplication(0x0d, State[i * Nb]) ^ GFMultiplication(0x09, State[i * Nb + 1]) ^ GFMultiplication(0x0e, State[i * Nb + 2]) ^ GFMultiplication(0x0b, State[i * Nb + 3]);
		Temp[3] = GFMultiplication(0x0b, State[i * Nb]) ^ GFMultiplication(0x0d, State[i * Nb + 1]) ^ GFMultiplication(0x09, State[i * Nb + 2]) ^ GFMultiplication(0x0e, State[i * Nb + 3]);
		memcpy(&State[i * Nb], Temp, sizeof(Temp));
	}

	return;
}

// AddRoundKey 関数
// word 毎に round key と state の xor を計算する
VOID WINAPI AddRoundKey(BYTE* State, // 4 * Nb
	DWORD* W)
{
	BYTE i;
	DWORD* pState = (DWORD*)State;
	const BYTE Nb = 4;

	for (i = 0; i < Nb; i++) {
		pState[i] ^= W[i];
	}

	return;
}

// RotWord 関数
// wordを右回転する
// a3 a2 a1 a0 -> a0 a3 a2 a1
DWORD RotWord(DWORD word)
{
	return word << 24 | word >> 8;
}

// SubWord 関数
// 4 バイト値を 1 バイトずつに分解しそれぞれの SBox 値を取得し、その結果を 4 バイト値にまとめる
DWORD WINAPI SubWord(DWORD word)
{
	DWORD dwSubWord = word;
	BYTE* pSubWord = (BYTE*)&dwSubWord;

	pSubWord[0] = SBox[pSubWord[0]];
	pSubWord[1] = SBox[pSubWord[1]];
	pSubWord[2] = SBox[pSubWord[2]];
	pSubWord[3] = SBox[pSubWord[3]];

	return dwSubWord;
}

// KeyExpansion 関数
// 暗号化鍵 (Key) から Round Key (W) を作成する
VOID WINAPI KeyExpansion(DWORD* Key, DWORD* W)
{
	DWORD uTemp;
	BYTE Nk = KeyTable[CurrentAESBitLength];
	BYTE Nr = RoundTable[CurrentAESBitLength];
	BYTE i;
	const BYTE Nb = 4;

	// i が Nk から Nb * (Nr+1) まで増加する時の x^(i-1) mod x^8 + x^4 + x^3 + x + 1 の計算結果を取得する
	const DWORD RCon[] = {
	  0x00000000, // invalid
	  0x00000001, // x^0
	  0x00000002, // x^1
	  0x00000004, // x^2
	  0x00000008, // x^3
	  0x00000010, // x^4
	  0x00000020, // x^5
	  0x00000040, // x^6
	  0x00000080, // x^7
	  0x0000001B, // x^4 + x^3 + x^1 + x^0
	  0x00000036, // x^5 + x^4 + x^2 + x^1
	};

	memcpy(W, Key, Nk * 4);
	for (i = Nk; i < Nb * (Nr + 1); i++)
	{
		uTemp = W[i - 1];
		if (i % Nk == 0)
		{
			uTemp = SubWord(RotWord(uTemp)) ^ RCon[i / Nk];
		}
		else if (6 < Nk && i % Nk == 4)
		{
			uTemp = SubWord(uTemp);
		}
		W[i] = W[i - Nk] ^ uTemp;
	}
}

// Cipher 関数
// AES 暗号化を行う
VOID WINAPI Cipher(BYTE* in, BYTE* out, DWORD* W)
{
	BYTE i;
	BYTE Nr = RoundTable[CurrentAESBitLength];
	const BYTE Nb = 4;
	BYTE* state; // state[4,Nb] 

	state = out;

	memcpy(state, in, 4 * Nb);
	AddRoundKey(state, &W[0]);
	for (i = 1; i < Nr; i++) {
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, &W[Nb * i]);
	}
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, &W[Nb * Nr]);

	return;
}

// InvCipher 関数
// AES 複合化を行う
VOID WINAPI InvCipher(BYTE* in, BYTE* out, DWORD* W)
{
	BYTE i;
	BYTE Nr = RoundTable[CurrentAESBitLength];
	const BYTE Nb = 4;
	BYTE* state; // state[4,Nb] 

	state = out;
	memcpy(state, in, 4 * Nb);
	AddRoundKey(state, &W[Nb * Nr]);
	for (i = Nr - 1; 1 <= i; i--) {
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, &W[Nb * i]);
		InvMixColumns(state);
	}
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, &W[0]);

	return;
}

// CipherAndInvCipher 関数
// AES による暗号化と複合化のテスト
VOID WINAPI CipherAndInvCipher(DWORD* Key, DWORD* in)
{
	DWORD W[60], out[4], inv[4];
	BYTE Nk = KeyTable[CurrentAESBitLength];
	BYTE i, * pTemp;

	pTemp = (BYTE*)Key;
	printf("%-21s =", "Cipher Key");
	for (i = 0; i < Nk * 4; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	// Round Key の作成
	KeyExpansion(Key, W);

	pTemp = (BYTE*)in;
	printf("%-21s =", "Input");
	for (i = 0; i < 16; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	// AES 暗号化
	Cipher((BYTE*)in, (BYTE*)out, W);

	pTemp = (BYTE*)out;
	printf("%-21s =", "Output");
	for (i = 0; i < 16; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	// AES 複合化
	InvCipher((BYTE*)out, (BYTE*)inv, W);

	pTemp = (BYTE*)inv;
	printf("%-21s =", "Input(Inv)");
	for (i = 0; i < 16; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	return;
}

// CbcXor
// CBC による暗号化の際行われる、平文と、IV や1つ前の暗号化文との XOR を行う
// どちらも 16 Bytes
VOID WINAPI CbcXor(BYTE* P, BYTE* Q, BYTE* pDest) // 4 * Nb
{
	const BYTE Nb = 4;
	DWORD i;

	for (i = 0; i < 4 * Nb; i++)
	{
		pDest[i] = P[i] ^ Q[i];
	}

	return;
}

// AesCbcEncrypt 関数
// CBC を用いた AES による暗号化を行う
//                Message 1                         Message 2                              Message N
//                   |                                 |                                      |
// IV --------------xor            +------------------xor                 +------------------xor
//                   |             |                   |                  |                   |
//                   v             |                   v                  |                   v
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+
// Key ->|block cipher encryption| | Key ->|block cipher encryption|      | Key ->|block cipher encryption|
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+ 
//                   |             |                   |                  |                   |
//                   +-------------+                   +---------- ...  --+                   |
//                   |                                 |                                      |
//                   v                                 v                                      v
//              Cipher Text 1                     Cipher Text 2                         Cipher Text N
VOID WINAPI AesCbcEncrypt(BYTE* IV, BYTE* Key, BYTE* in, DWORD cbIn, BYTE* out, LPDWORD lpcbOut)
{
	DWORD W[60];
	BYTE* pInCurrent, outTemp[16], MsgTemp[16];
	DWORD cbRemain;

	if (cbIn % 16 != 0)
	{
		return;
	}
	cbRemain = cbIn;
	if (cbRemain > 0)
	{
		// Round Key の作成
		KeyExpansion((DWORD*)Key, W);

		// 16 バイト毎のメッセージの変換

		// 平文と IV の XOR
		CbcXor(IV, in, MsgTemp);

		// XOR した結果を用いて AES 暗号化
		Cipher(MsgTemp, outTemp, W);

		cbRemain -= 16;
		pInCurrent = &in[16];

		// 結果を出力用バッファにコピー
		memcpy(out, outTemp, 16);
		*lpcbOut = 16;

		while (cbRemain > 0)
		{
			// 次の平文との XOR
			CbcXor(pInCurrent, outTemp, MsgTemp);

			// XOR した結果を用いて AES 暗号化
			Cipher(MsgTemp, outTemp, W);

			// 結果を出力用バッファにコピー
			memcpy(&out[cbIn - cbRemain], outTemp, 16);
			*lpcbOut += 16;

			cbRemain -= 16;
			pInCurrent = &in[cbIn - cbRemain];
		}
	}

	return;
}

// AesCbcDecrypt 関数
// CBC を用いた Aes による複合化を行う
//              Cipher Text 1                     Cipher Text 2                         Cipher Text N
//                   |                                 |                                      |
//                   +-------------+                   +---------- ...  --+                   |
//                   |             |                   |                  |                   |
//                   v             |                   v                  |                   v
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+
// Key ->|block cipher encryption| | Key ->|block cipher encryption|      | Key ->|block cipher encryption|
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+ 
//                   |             |                   |                  |                   |
// IV --------------xor            +------------------xor                 +------------------xor
//                   |                                 |                                      |
//                   v                                 v                                      v
//                Message 1                         Message 2                              Message N
VOID WINAPI AesCbcDecrypt(BYTE* IV, BYTE* Key, BYTE* in, DWORD cbIn, BYTE* out, LPDWORD lpcbOut)
{
	DWORD W[60];
	BYTE* pInCurrent, inTemp[16], outTemp[16], MsgTemp[16];
	DWORD cbRemain;

	if (cbIn % 16 != 0)
	{
		return;
	}
	cbRemain = cbIn;
	if (cbRemain > 0)
	{
		// Round Key の作成
		KeyExpansion((DWORD*)Key, W);

		// AES 複合化
		InvCipher(in, MsgTemp, W);

		// 複合化結果と IV の XOR
		CbcXor(IV, MsgTemp, outTemp);

		cbRemain -= 16;
		pInCurrent = &in[16];

		// 結果を出力用バッファにコピー
		memcpy(out, outTemp, 16);
		*lpcbOut = 16;

		memcpy(inTemp, in, 16);

		while (cbRemain > 0)
		{
			// AES 複合化
			InvCipher(pInCurrent, MsgTemp, W);

			// 複合化結果と前の暗号化文の XOR
			CbcXor(inTemp, MsgTemp, outTemp);

			memcpy(inTemp, pInCurrent, 16);

			// 結果を出力用バッファにコピー
			memcpy(&out[cbIn - cbRemain], outTemp, 16);
			*lpcbOut += 16;

			cbRemain -= 16;
			pInCurrent = &in[cbIn - cbRemain];
		}
	}

	return;
}

VOID WINAPI AesCbcEncryptAndDecrypt(BYTE* IV, BYTE* Key, BYTE* in, DWORD cbIn)
{
	BYTE* out, * inv;
	DWORD cbOut, cbInv;
	BYTE i, * pTemp;
	BYTE Nk = KeyTable[CurrentAESBitLength];

	pTemp = (BYTE*)Key;
	printf("%-21s =", "Cipher Key");
	for (i = 0; i < Nk * 4; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	pTemp = (BYTE*)IV;
	printf("%-21s =", "Initialization Vector");
	for (i = 0; i < 16; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	pTemp = (BYTE*)in;
	printf("%-21s =", "Input");
	for (i = 0; i < cbIn; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	out = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);

	AesCbcEncrypt(IV, Key, in, cbIn, out, &cbOut);

	pTemp = (BYTE*)out;
	printf("%-21s =", "Output");
	for (i = 0; i < cbOut; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	inv = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);

	AesCbcDecrypt(IV, Key, out, cbOut, inv, &cbInv);

	pTemp = (BYTE*)inv;
	printf("%-21s =", "Input(Inv)");
	for (i = 0; i < cbInv; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	HeapFree(GetProcessHeap(), 0, out);
	HeapFree(GetProcessHeap(), 0, inv);

	return;
}

// CfbXor
// CFB による暗号化の際行われる、暗号化文と入力データのセグメント長の XOR を行う
VOID WINAPI CfbXor(BYTE* P, BYTE* Q, DWORD dwSegmentBitLength, BYTE* pDest)
{
	DWORD i;

	if (dwSegmentBitLength % 8 == 0)
	{
		// Segment Bits が 8 の倍数 (バイト) の場合
		for (i = 0; i < dwSegmentBitLength / 8; i++)
		{
			pDest[i] = P[i] ^ Q[i];
		}
	}
	else
	{
		if (dwSegmentBitLength != 1)
		{
			return;
		}
		*pDest = *P ^ *Q;
	}

	return;
}

// AesCfbEncrypt 関数
// CFB を用いた AES による暗号化を行う
// IV ---------------+             +-------------------+                  +-------------------+ 
//                   |             |                   |                  |                   |
//                   |             |        (block - segment bits)        |        (block - segment bits)
//                   v             |                   v                  |                   v
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+
//       |Input Block 1          | |       |Input Block 2          |      |       |Input Block N          |
//       |(128 bits)             | |       |(128 - s bits)|(s bits)|      |       |(128 - s bits)|(s bits)|
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+
// Key ->|block cipher encryption| | Key ->|block cipher encryption|      | Key ->|block cipher encryption|
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+ 
//                   |             |                   |                  |                   |
//   Message 1 -----xor            |   Message 2 -----xor                 |   Message N -----xor
//   (Segment Bits)  |             |   (Segment Bits)  |                  |   (Segment Bits)  |
//                   |             |                   |                  |                   |
//                   +-------------+                   +---------- ...  --+                   |
//                   |                                 |                                      |
//                   v                                 v                                      v
//         Cipher Text 1 (s bits)            Cipher Text 2 (s bits)                 Cipher Text N (s bits)
VOID WINAPI AesCfbEncrypt(BYTE* IV, BYTE* Key, DWORD dwSegmentBits, BYTE* in, DWORD cbIn, BYTE* out, LPDWORD lpcbOut)
{
	DWORD W[60];
	BYTE* pInCurrent, inTemp[16], outTemp[16], MsgTemp[16];
	DWORD cbRemain, cbSegment;

	// 入力データサイズが Segment Bits の倍数で無い場合終了
	if ((cbIn * 8) % dwSegmentBits != 0)
	{
		return;
	}

	// Segment Bits が IV (16 バイト) を超えている場合終了
	if (dwSegmentBits > 128)
	{
		return;
	}

	if (dwSegmentBits % 8 == 0)
	{
		// Segment Bits が 8 の倍数 (バイト) である場合
		cbRemain = cbIn;
		if (cbRemain > 0)
		{
			// Round Key の作成
			KeyExpansion((DWORD*)Key, W);

			// IV の AES 暗号化
			Cipher(IV, MsgTemp, W);

			// 平文と結果の XOR
			CfbXor(in, MsgTemp, dwSegmentBits, outTemp);
			cbSegment = dwSegmentBits / 8;

			// 結果を出力用バッファにコピー
			memcpy(out, outTemp, cbSegment);
			*lpcbOut = cbSegment;

			cbRemain -= cbSegment;
			pInCurrent = &in[cbSegment];

			// セグメント分 IV を左シフトし、セグメント分を挿入して入力データを作成
			if (cbSegment != 16)
			{
				memcpy(inTemp, &IV[cbSegment], 16 - cbSegment);
				memcpy(&inTemp[16 - cbSegment], outTemp, cbSegment);
			}
			else
			{
				memcpy(inTemp, outTemp, cbSegment);
			}

			while (cbRemain > 0)
			{
				// 前の結果から作成した入力データを AES 暗号化
				Cipher(inTemp, MsgTemp, W);

				// 結果と平文の XOR
				CfbXor(pInCurrent, MsgTemp, dwSegmentBits, outTemp);

				// 結果を出力用バッファにコピー
				memcpy(&out[cbIn - cbRemain], outTemp, cbSegment);
				*lpcbOut += cbSegment;

				cbRemain -= cbSegment;
				pInCurrent = &in[cbIn - cbRemain];

				// セグメント分入力データを左シフトし、セグメント分を挿入して入力データを作成
				if (cbSegment != 16)
				{
					memcpy(inTemp, &inTemp[cbSegment], 16 - cbSegment);
					memcpy(&inTemp[16 - cbSegment], outTemp, cbSegment);
				}
				else
				{
					memcpy(inTemp, outTemp, cbSegment);
				}
			}
		}
	}

	return;
}


// AesCfbDecrypt 関数
// CFB を用いた Aes による複合化を行う
// IV ---------------+             +-------------------+              +--- ... -----------+ 
//                   |             |                   |              |                   |
//                   |             |        (block - segment bits)    |        (block - segment bits)
//                   v             |                   v              |                   v
//       +-----------+-----------+ |       +-----------+-----------+  |       +-----------+-----------+
//       |Input Block 1          | |       |Input Block 2          |  |       |Input Block N          |
//       |(128 bits)             | |       |(128 - s bits)|(s bits)|  |       |(128 - s bits)|(s bits)|
//       +-----------+-----------+ |       +-----------+-----------+  |       +-----------+-----------+
// Key ->|block cipher encryption| | Key ->|block cipher encryption|  | Key ->|block cipher encryption|
//       +-----------+-----------+ |       +-----------+-----------+  |       +-----------+-----------+ 
//                   |             |                   |              |                   |
//                   |             |                   |              |                   |
//                   |             |                   |              |                   |
//                  xor------ Cipher Text 1           xor----- Cipher Text 2             xor----- Cipher Text N
//                   |                                 |                                  |
//                   v                                 v                                  v
//               Message 1                         Message 2                          Message N
VOID WINAPI AesCfbDecrypt(BYTE* IV, BYTE* Key, DWORD dwSegmentBits, BYTE* in, DWORD cbIn, BYTE* out, LPDWORD lpcbOut)
{
	DWORD W[60];
	BYTE* pInCurrent, inTemp[16], outTemp[16], MsgTemp[16];
	DWORD cbRemain, cbSegment;

	// 入力データサイズが Segment Bits の倍数で無い場合終了
	if ((cbIn * 8) % dwSegmentBits != 0)
	{
		return;
	}

	// Segment Bits が IV (16 バイト) を超えている場合終了
	if (dwSegmentBits > 128)
	{
		return;
	}

	if (dwSegmentBits % 8 == 0)
	{
		// Segment Bits が 8 の倍数 (バイト) である場合
		cbRemain = cbIn;
		if (cbRemain > 0)
		{
			// Round Key の作成
			KeyExpansion((DWORD*)Key, W);

			// IV の AES 暗号化
			Cipher(IV, MsgTemp, W);

			// 入力データと結果の XOR
			CfbXor(in, MsgTemp, dwSegmentBits, outTemp);
			cbSegment = dwSegmentBits / 8;

			// 結果を出力用バッファにコピー
			memcpy(out, outTemp, cbSegment);
			*lpcbOut = cbSegment;

			// セグメント分 IV を左シフトし、セグメント分を挿入して入力データを作成
			if (cbSegment != 16)
			{
				memcpy(inTemp, &IV[cbSegment], 16 - cbSegment);
				memcpy(&inTemp[16 - cbSegment], in, cbSegment);
			}
			else
			{
				memcpy(inTemp, in, cbSegment);
			}

			cbRemain -= cbSegment;
			pInCurrent = &in[cbSegment];

			while (cbRemain > 0)
			{
				// 入力データを AES 暗号化
				Cipher(inTemp, MsgTemp, W);

				// 結果と入力データの XOR
				CfbXor(pInCurrent, MsgTemp, dwSegmentBits, outTemp);

				// 結果を出力用バッファにコピー
				memcpy(&out[cbIn - cbRemain], outTemp, cbSegment);
				*lpcbOut += cbSegment;

				// セグメント分入力データを左シフトし、セグメント分を挿入して入力データを作成
				if (cbSegment != 16)
				{
					memcpy(inTemp, &inTemp[cbSegment], 16 - cbSegment);
					memcpy(&inTemp[16 - cbSegment], pInCurrent, cbSegment);
				}
				else
				{
					memcpy(inTemp, pInCurrent, cbSegment);
				}

				cbRemain -= cbSegment;
				pInCurrent = &in[cbIn - cbRemain];
			}
		}

	}

	return;
}


VOID WINAPI AesCfbEncryptAndDecrypt(BYTE* IV, BYTE* Key, DWORD dwSegmentBits, BYTE* in, DWORD cbIn)
{
	BYTE* out, * inv;
	DWORD cbOut, cbInv;
	BYTE i, * pTemp;
	BYTE Nk = KeyTable[CurrentAESBitLength];

	pTemp = (BYTE*)Key;
	printf("%-21s =", "Cipher Key");
	for (i = 0; i < Nk * 4; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	pTemp = (BYTE*)IV;
	printf("%-21s =", "Initialization Vector");
	for (i = 0; i < 16; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	pTemp = (BYTE*)in;
	printf("%-21s =", "Input");
	for (i = 0; i < cbIn; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	out = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);

	AesCfbEncrypt(IV, Key, dwSegmentBits, in, cbIn, out, &cbOut);

	pTemp = (BYTE*)out;
	printf("%-21s =", "Output");
	for (i = 0; i < cbOut; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	inv = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);

	AesCfbDecrypt(IV, Key, dwSegmentBits, out, cbOut, inv, &cbInv);

	pTemp = (BYTE*)inv;
	printf("%-21s =", "Input(Decrypt)");
	for (i = 0; i < cbInv; i++)
	{
		printf(" %02x", pTemp[i]);
	}
	printf("\r\n");

	HeapFree(GetProcessHeap(), 0, out);
	HeapFree(GetProcessHeap(), 0, inv);

	return;
}

INT main(INT argc, CHAR* argv[])
{
	// AES による暗号化テスト

	printf("AES\r\n");

	// サンプル元
	// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf

	BYTE a, b, c;

	printf("GF\r\n");
	a = 0x57;
	b = 2;
	c = GFMultiplication(a, b);
	printf("GF(%x, %x) = %x\r\n", a, b, c);
	printf("\r\n");

	b = 4;
	c = GFMultiplication(a, b);
	printf("GF(%x, %x) = %x\r\n", a, b, c);
	printf("\r\n");

	b = 8;
	c = GFMultiplication(a, b);
	printf("GF(%x, %x) = %x\r\n", a, b, c);
	printf("\r\n");

	b = 0x10;
	c = GFMultiplication(a, b);
	printf("GF(%x, %x) = %x\r\n", a, b, c);
	printf("\r\n");

	// Example 1
	// Cipher Key = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c (128bit)
	// Input = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
	// Output = 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32

	BYTE AesExample1_Key[56] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	BYTE AesExample1_Input[16] = { 0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34 };

	CurrentAESBitLength = AES128;
	CipherAndInvCipher((DWORD*)AesExample1_Key, (DWORD*)AesExample1_Input);
	printf("\r\n");

	// Example 2
	// Cipher Key = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f (128bit)
	// Input = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
	// Output = 69 c4 e0 d8 6a 7b 04 30 d8 cd b7 80 70 b4 c5 5a

	BYTE AesExample2_Key[56] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
	BYTE AesExample2_Input[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

	CipherAndInvCipher((DWORD*)AesExample2_Key, (DWORD*)AesExample2_Input);
	printf("\r\n");

	// Example 3
	// Cipher Key = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 (192bit)
	// Input = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
	// Output = dd a9 7c a4 86 4c df e0 6e af 70 a0 ec 0d 71 91

	CurrentAESBitLength = AES192;
	BYTE AesExample3_Key[56] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
	BYTE AesExample3_Input[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

	CipherAndInvCipher((DWORD*)AesExample3_Key, (DWORD*)AesExample3_Input);
	printf("\r\n");

	// Example 4
	// Cipher Key = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f (256bit)
	// Input = 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff
	// Output = 8e a2 b7 ca 51 67 45 bf ea fc 49 90 4b 49 60 89

	CurrentAESBitLength = AES256;
	BYTE AesExample4_Key[56] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
	BYTE AesExample4_Input[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

	CipherAndInvCipher((DWORD*)AesExample4_Key, (DWORD*)AesExample4_Input);
	printf("\r\n");

	// CBC による暗号化テスト

	printf("AES(CBC)\r\n");

	// サンプル元
	// https://datatracker.ietf.org/doc/html/rfc3602 

	// Example 1
	// Cipher Key = 06 a9 21 40 36 b8 a1 5b 51 2e 03 d5 34 12 00 06 (128bit)
	// IV = 3d af ba 42 9d 9e b4 30 b4 22 da 80 2c 9f ac 41
	// Input = "Single block msg"
	// Output = e3 53 77 9c 10 79 ae b8 27 08 94 2d be 77 18 1a

	CurrentAESBitLength = AES128;
	BYTE AesCbcExample1_Key[56] = { 0x06, 0xa9, 0x21, 0x40, 0x36, 0xb8, 0xa1, 0x5b, 0x51, 0x2e, 0x03, 0xd5, 0x34, 0x12, 0x00, 0x06 };
	BYTE AesCbcExample1_IV[16] = { 0x3d, 0xaf, 0xba, 0x42, 0x9d, 0x9e, 0xb4, 0x30, 0xb4, 0x22, 0xda, 0x80, 0x2c, 0x9f, 0xac, 0x41 };
	CHAR AesCbcExample1_Input[] = "Single block msg";

	AesCbcEncryptAndDecrypt(AesCbcExample1_IV, AesCbcExample1_Key, (BYTE*)AesCbcExample1_Input, 16);
	printf("\r\n");

	// Example 2
	// Cipher Key = c2 86 69 6d 88 7c 9a a0 61 1b bb 3e 20 25 a4 5a (128bit)
	// IV = 56 2e 17 99 6d 09 3d 28 dd b3 ba 69 5a 2e 6f 58
	// Input = 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f
	// Output = d2 96 cd 94 c2 cc cf 8a 3a 86 30 28 b5 e1 dc 0a 75 86 60 2d 25 3c ff f9 1b 82 66 be a6 d6 1a b1 

	BYTE AesCbcExample2_Key[56] = { 0xc2, 0x86, 0x69, 0x6d, 0x88, 0x7c, 0x9a, 0xa0, 0x61, 0x1b, 0xbb, 0x3e, 0x20, 0x25, 0xa4, 0x5a };
	BYTE AesCbcExample2_IV[16] = { 0x56, 0x2e, 0x17, 0x99, 0x6d, 0x09, 0x3d, 0x28, 0xdd, 0xb3, 0xba, 0x69, 0x5a, 0x2e, 0x6f, 0x58 };
	BYTE AesCbcExample2_Input[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

	AesCbcEncryptAndDecrypt(AesCbcExample2_IV, AesCbcExample2_Key, (BYTE*)AesCbcExample2_Input, 32);
	printf("\r\n");

	// Example 3
	// Cipher Key = 6c 3e a0 47 76 30 ce 21 a2 ce 33 4a a7 46 c2 cd (128bit)
	// IV = c7 82 dc 4c 09 8c 66 cb d9 cd 27 d8 25 68 2c 81
	// Input = "This is a 48-byte message (exactly 3 AES blocks)"
	// Output = d0 a0 2b 38 36 45 17 53 d4 93 66 5d 33 f0 e8 86 2d ea 54 cd b2 93 ab c7 50 69 39 27 67 72 f8 d5 02 1c 19 21 6b ad 52 5c 85 79 69 5d 83 ba 26 84

	BYTE AesCbcExample3_Key[56] = { 0x6c, 0x3e, 0xa0, 0x47, 0x76, 0x30, 0xce, 0x21, 0xa2, 0xce, 0x33, 0x4a, 0xa7, 0x46, 0xc2, 0xcd };
	BYTE AesCbcExample3_IV[16] = { 0xc7, 0x82, 0xdc, 0x4c, 0x09, 0x8c, 0x66, 0xcb, 0xd9, 0xcd, 0x27, 0xd8, 0x25, 0x68, 0x2c, 0x81 };
	CHAR AesCbcExample3_Input[] = "This is a 48-byte message (exactly 3 AES blocks)";

	AesCbcEncryptAndDecrypt(AesCbcExample3_IV, AesCbcExample3_Key, (BYTE*)AesCbcExample3_Input, 48);
	printf("\r\n");

	// Example 4
	// Cipher Key = 8c e8 2e ef be a0 da 3c 44 69 9e d7 db 51 b7 d9 (128bit)
	// IV = 56 e4 7a 38 c5 59 89 74 bc 46 90 3d ba 29 03 49
	// Input = a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af b0 b1 b2 b3 b4 b5 b6 b7 b8 b9 ba bb bc bd be bf c0 c1 c2 c3 c4 c5 c6 c7 c8 c9 ca cb cc cd ce cf d0 d1 d2 d3 d4 d5 d6 d7 d8 d9 da db dc dd de df
	// Output = c3 0e 32 ff ed c0 77 4e 6a ff 6a f0 86 9f 71 aa 0f 3a f0 7a 9a 31 a9 c6 84 db 20 7e b0 ef 8e 4e 35 90 7a a6 32 c3 ff df 86 8b b7 b2 9d 3d 46 ad 83 ce 9f 9a 10 2e e9 9d 49 a5 3e 87 f4 c3 da 55

	BYTE AesCbcExample4_Key[56] = { 0x56, 0xe4, 0x7a, 0x38, 0xc5, 0x59, 0x89, 0x74, 0xbc, 0x46, 0x90, 0x3d, 0xba, 0x29, 0x03, 0x49 };
	BYTE AesCbcExample4_IV[16] = { 0x8c, 0xe8, 0x2e, 0xef, 0xbe, 0xa0, 0xda, 0x3c, 0x44, 0x69, 0x9e, 0xd7, 0xdb, 0x51, 0xb7, 0xd9 };
	BYTE AesCbcExample4_Input[64] = { 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
		0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
		0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
		0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf };

	AesCbcEncryptAndDecrypt(AesCbcExample4_IV, AesCbcExample4_Key, AesCbcExample4_Input, 64);
	printf("\r\n");

	// CFB による暗号化テスト

	printf("AES(CFB)\r\n");

	// サンプル元
	// https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/examples/aes_cfb.pdf

	// Example 1
	// Segment Length = 128
	// Cipher Key = 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C (128bit)
	// IV = 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
	// Input = 6B C1 BE E2 2E 40 9F 96 E9 3D 7E 11 73 93 17 2A AE 2D 8A 57 1E 03 AC 9C 9E B7 6F AC 45 AF 8E 51 30 C8 1C 46 A3 5C E4 11 E5 FB C1 19 1A 0A 52 EF F6 9F 24 45 DF 4F 9B 17 AD 2B 41 7B E6 6C 37 10
	// Output = 3b 3f d9 2e b7 2d ad 20 33 34 49 f8 e8 3c fb 4a c8 a6 45 37 a0 b3 a9 3f cd e3 cd ad 9f 1c e5 8b 26 75 1f 67 a3 cb b1 40 b1 80 8c f1 87 a4 f4 df c0 4b 05 35 7c 5d 1c 0e ea c4 c6 6f 9f f7 f2 e6

	CurrentAESBitLength = AES128;
	DWORD AesCfbExample1_SegmentLength = 128;
	BYTE AesCfbExample1_Key[56] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
	BYTE AesCfbExample1_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	BYTE AesCfbExample1_Input[64] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
		0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
		0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
		0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10 };

	AesCfbEncryptAndDecrypt(AesCfbExample1_IV, AesCfbExample1_Key, AesCfbExample1_SegmentLength, AesCfbExample1_Input, 64);
	printf("\r\n");

	// Example 2
	// Segment Length = 8
	// Cipher Key = 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C (128bit)
	// IV = 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 
	// Input = 6B C1 BE E2 2E 40 9F 96 E9 3D 7E 11 73 93 17 2A
	// Output = 3b 79 42 4c 9c 0d d4 36 ba ce 9e 0e d4 58 6a 4f

	DWORD AesCfbExample2_SegmentLength = 8;
	BYTE AesCfbExample2_Key[56] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
	BYTE AesCfbExample2_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	BYTE AesCfbExample2_Input[16] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };

	AesCfbEncryptAndDecrypt(AesCfbExample2_IV, AesCfbExample2_Key, AesCfbExample2_SegmentLength, AesCfbExample2_Input, 16);
	printf("\r\n");

	// Example 3
	// Cipher Key = 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C (128bit)
	// IV = 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 
	// Input = 6B C1
	// Output = 69 C8

	DWORD AesCfbExample3_SegmentLength = 1;
	BYTE AesCfbExample3_Key[56] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
	BYTE AesCfbExample3_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	BYTE AesCfbExample3_Input[2] = { 0x6B, 0xC1 };

	AesCfbEncryptAndDecrypt(AesCfbExample3_IV, AesCfbExample3_Key, AesCfbExample3_SegmentLength, AesCfbExample3_Input, 2);
	printf("\r\n");

	// Example 4
	// Cipher Key = 8E 73 B0 F7 DA 0E 64 52 C8 10 F3 2B 80 90 79 E5 62 F8 EA D2 52 2C 6B 7B (192bit)
	// IV = 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 
	// Input = 6B C1 BE E2 2E 40 9F 96 E9 3D 7E 11 73 93 17 2A AE 2D 8A 57 1E 03 AC 9C 9E B7 6F AC 45 AF 8E 51 30 C8 1C 46 A3 5C E4 11 E5 FB C1 19 1A 0A 52 EF F6 9F 24 45 DF 4F 9B 17 AD 2B 41 7B E6 6C 37 10
	// Output = cd c8 0d 6f dd f1 8c ab 34 c2 59 09 c9 9a 41 74 67 ce 7f 7f 81 17 36 21 96 1a 2b 70 17 1d 3d 7a 2e 1e 8a 1d d5 9b 88 b1 c8 e6 0f ed 1e fa c4 c9 c0 5f 9f 9c a9 83 4f a0 42 ae 8f ba 58 4b 09 ff

	CurrentAESBitLength = AES192;
	DWORD AesCfbExample4_SegmentLength = 128;
	BYTE AesCfbExample4_Key[56] = { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B };
	BYTE AesCfbExample4_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	BYTE AesCfbExample4_Input[64] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
		0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
		0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
		0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10 };

	AesCfbEncryptAndDecrypt(AesCfbExample4_IV, AesCfbExample4_Key, AesCfbExample4_SegmentLength, AesCfbExample4_Input, 64);
	printf("\r\n");

	return 0;
}