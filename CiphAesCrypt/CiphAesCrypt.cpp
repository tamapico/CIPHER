#include <Windows.h>
#include <stdio.h>

// AES (Advanced Encryption Standard) による暗号化

// 参考
// ADVANCED ENCRYPTION STANDARD (AES)
// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf

// テスト
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_ModesA_All.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf

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

// Figure 7. S-box:  substitution values for the byte xy (in hexadecimal format).
// バイト値の1対1の非線形置換表
static const BYTE SBox[256] = {
	//     0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
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

// Figure 14. Inverse S-box: substitution values for the byte xy (in hexadecimal format).
// バイト値の1対1の非線形置換表
// SBox の逆バージョン
static const BYTE InvSBox[256] = {
	//     0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
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

// Figure 10.  AddRoundKey() XORs each column of the State with a word from the key schedule.
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

// Figure 11.  Pseudo Code for Key Expansion.
// KeyExpansion 関数
// 暗号化鍵 (Key) から Round Key (W) を作成する
VOID WINAPI KeyExpansion(BYTE* Key, // 4*Nk
	DWORD* W, // Nb*(Nr+1)
	BYTE Nk)
{
	BYTE i;
	for (i = 0; i < Nk; i++)
	{
		W[i] = Key[4 * i + 3];
		W[i] <<= 8;
		W[i] += Key[4 * i + 2];
		W[i] <<= 8;
		W[i] += Key[4 * i + 1];
		W[i] <<= 8;
		W[i] += Key[4 * i];
	}

	const BYTE Nb = 4;
	BYTE Nr = RoundTable[CurrentAESBitLength];
	DWORD temp;

	for (i = Nk; i < Nb * (Nr + 1); i++)
	{
		temp = W[i - 1];

		if (i % Nk == 0)
		{
			temp = SubWord(RotWord(temp)) ^ RCon[i / Nk];
		}
		else if (Nk > 6 && i % Nk == 4)
		{
			temp = SubWord(temp);
		}

		W[i] = W[i - Nk] ^ temp;
	}

	return;
}

// Figure 5.  Pseudo Code for the Cipher.
// Cipher 関数
// AES 暗号化を行う
VOID WINAPI Cipher(BYTE* in, BYTE* out, DWORD* W)
{
	BYTE i, Nr = RoundTable[CurrentAESBitLength], state[16]; // state[4,Nb] 
	const BYTE Nb = 4;

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

	memcpy(out, state, 16);

	return;
}

// Figure 12.  Pseudo Code for the Inverse Cipher.
// InvCipher 関数
// AES 複合化を行う
VOID WINAPI InvCipher(BYTE* in, BYTE* out, DWORD* W)
{
	BYTE i, Nr = RoundTable[CurrentAESBitLength], state[16]; // state[4,Nb] 
	const BYTE Nb = 4;

	memcpy(state, in, 16);

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

	memcpy(out, state, 16);

	return;
}

// AesEcbEncrypt 関数
// EBC を用いた AES による暗号化、複合化を行う
//              Plane Text 1                     Plane Text 2                     Plane Text N
//                   |                                |                                |
//                   |                                |                                |
//                   v                                v                                v
//       +-----------+-----------+        +-----------+-----------+        +-----------+-----------+
// Key ->|block cipher encryption|  Key ->|block cipher encryption|  Key ->|block cipher encryption|
//       +-----------+-----------+        +-----------+-----------+        +-----------+-----------+ 
//                   |                                |                                |
//                   |                                |                                |
//                   v                                v                                v
//              Cipher Text 1                    Cipher Text 2                   Cipher Text N
VOID WINAPI AesEcbEncrypt(BYTE* in, DWORD cbIn, BYTE* Key, BYTE* out)
{
	DWORD i, W[60];

	KeyExpansion(Key, W, KeyTable[CurrentAESBitLength]);

	// AES 暗号化
	Cipher(in, out, W);
	for (i = 16; i < cbIn; i += 16)
	{
		Cipher(&in[i], &out[i], W);
	}

	return;
}

// AesEcbDecrypt 関数
// ECB を用いた Aes による複合化を行う
//              Cipher Text 1                    Cipher Text 2                   Cipher Text N
//                   |                                |                                |
//                   |                                |                                |
//                   v                                v                                v
//       +-----------+-----------+        +-----------+-----------+        +-----------+-----------+
// Key ->|block cipher decryption|  Key ->|block cipher decryption|  Key ->|block cipher decryption|
//       +-----------+-----------+        +-----------+-----------+        +-----------+-----------+ 
//                   |                                |                                |
//                   |                                |                                |
//                   v                                v                                v
//              Plane Text 1                    Plane Text 2                     Plane Text N
VOID WINAPI AesEcbDecrypt(BYTE* in, DWORD cbIn, BYTE* Key, BYTE* out)
{
	DWORD i, W[60];

	KeyExpansion(Key, W, KeyTable[CurrentAESBitLength]);

	// AES 複合化
	InvCipher(in, out, W);
	for (i = 16; i < cbIn; i += 16)
	{
		InvCipher(&in[i], &out[i], W);
	}

	return;
}

VOID WINAPI Xor(BYTE* in1, BYTE* in2, DWORD cbIn, BYTE* out)
{
	DWORD i;

	for (i = 0; i < cbIn; i++)
	{
		out[i] = in1[i] ^ in2[i];
	}

	return;
}

// AesCbcEncrypt 関数
// CBC を用いた AES による暗号化を行う
//               Plane Text 1                      Plane Text 2                          Plane Text N
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
VOID WINAPI AesCbcEncrypt(BYTE* in, DWORD cbIn, BYTE* IV, BYTE* Key, BYTE* out)
{
	DWORD i, W[60];
	BYTE inTemp[16], outTemp[16];

	KeyExpansion(Key, W, KeyTable[CurrentAESBitLength]);

	// AES-CBC による暗号化
	Xor(in, IV, 16, inTemp);
	Cipher(inTemp, outTemp, W);
	memcpy(out, outTemp, 16);
	for (i = 16; i < cbIn; i += 16)
	{
		Xor(&in[i], outTemp, 16, inTemp);
		Cipher(inTemp, outTemp, W);
		memcpy(&out[i], outTemp, 16);
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
// Key ->|block cipher decryption| | Key ->|block cipher decryption|      | Key ->|block cipher decryption|
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+ 
//                   |             |                   |                  |                   |
// IV --------------xor            +------------------xor                 +------------------xor
//                   |                                 |                                      |
//                   v                                 v                                      v
//              Plane Text 1                      Plane Text 2                          Plane Text N
VOID WINAPI AesCbcDecrypt(BYTE* in, DWORD cbIn, BYTE* IV, BYTE* Key, BYTE* out)
{
	DWORD i, W[60];
	BYTE inTemp[16], outTemp[16];

	KeyExpansion(Key, W, KeyTable[CurrentAESBitLength]);

	// AES-CBC による複合化
	InvCipher(in, inTemp, W);
	Xor(inTemp, IV, 16, outTemp);
	memcpy(out, outTemp, 16);
	for (i = 16; i < cbIn; i += 16)
	{
		InvCipher(&in[i], inTemp, W);
		Xor(&in[i - 16], inTemp, 16, outTemp);
		memcpy(&out[i], outTemp, 16);
	}

	return;
}

// AesCfbEncrypt 関数
// CFB を用いた AES による暗号化を行う
// IV ---------------+------------>+-------------------+---------- ... -->+-------------------+ 
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
// Plane Text 1 ----xor            |  Plane Text 2 ---xor                 |   Plane Text N --xor
//   (Segment Bits)  |             |   (Segment Bits)  |                  |   (Segment Bits)  |
//                   |             |                   |                  |                   |
//                   +-------------+                   +---------- ...  --+                   |
//                   |                                 |                                      |
//                   v                                 v                                      v
//         Cipher Text 1 (s bits)            Cipher Text 2 (s bits)                 Cipher Text N (s bits)
VOID WINAPI AesCfbEncrypt(BYTE* in, DWORD cbIn, BYTE* IV, BYTE* Key, BYTE cbitSegment, BYTE* out)
{
	DWORD i, cbSegment, cbRemain, W[60];
	BYTE inTemp[16], MsgTemp[16], outTemp[16], * pInCurrent, temp, sbits, bitsCurrent, bitOr;

	// Segment Bits が IV (16 バイト) を超えている場合、もしくは 0 の場合終了
	if (cbitSegment > 128 || cbitSegment == 0)
	{
		return;
	}

	// 入力データサイズが Segment Bits の倍数で無い場合終了
	if ((cbIn * 8) % cbitSegment != 0)
	{
		return;
	}

	KeyExpansion(Key, W, KeyTable[CurrentAESBitLength]);

	if (cbitSegment % 8 == 0) // Segment Bits が 8 の倍数 (バイト) である場合
	{
		cbSegment = cbitSegment / 8;

		// AES-CFB による暗号化
		Cipher(IV, inTemp, W);
		Xor(in, inTemp, cbSegment, outTemp); // Segment Bits 分の xor
		memcpy(out, outTemp, cbSegment);// 結果を出力用バッファにコピー

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

		for (cbRemain = cbIn - cbSegment, pInCurrent = &in[cbSegment]; cbRemain > 0; cbRemain -= cbSegment, pInCurrent += cbSegment)
		{
			Cipher(inTemp, MsgTemp, W); // 前の結果から作成した入力データを AES 暗号化
			Xor(pInCurrent, MsgTemp, cbSegment, outTemp); // 結果と平文の XOR
			memcpy(&out[cbIn - cbRemain], outTemp, cbSegment); // 結果を出力用バッファにコピー

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
	else if (8 % cbitSegment == 0) // Segment Bits が 1, 2, 4 の場合
	{
		// AES-CFB による暗号化
		Cipher(IV, outTemp, W);
		sbits = (in[0] ^ outTemp[0]) >> (8 - cbitSegment); // Segment Bits 分 xor

		bitOr = 1;
		for (i = 1; i < cbitSegment; i++)
		{
			bitOr <<= 1;
			bitOr++;
		}

		// セグメント分入力データを左シフトし、セグメント分を挿入して入力データを作成
		for (i = 0; i < 15; i++)
		{
			inTemp[i] = IV[i] << cbitSegment;
			inTemp[i] |= IV[i + 1] >> (8 - cbitSegment);
		}
		inTemp[15] = IV[15] << cbitSegment;
		inTemp[15] |= sbits;

		bitsCurrent = cbitSegment;
		temp = sbits;
		for (cbRemain = cbIn; cbRemain > 0; cbRemain--)
		{
			while (bitsCurrent < 8)
			{
				Cipher(inTemp, outTemp, W);

				sbits = (((in[cbIn - cbRemain] << bitsCurrent) ^ outTemp[0]) >> (8 - cbitSegment)) & bitOr; // Segment Bits 分の xor
				temp <<= cbitSegment;
				temp |= sbits;
				bitsCurrent += cbitSegment;

				// セグメント分入力データを左シフトし、セグメント分を挿入して入力データを作成
				for (i = 0; i < 15; i++)
				{
					inTemp[i] = inTemp[i] << cbitSegment;
					inTemp[i] |= inTemp[i + 1] >> (8 - cbitSegment);
				}
				inTemp[15] = inTemp[15] << cbitSegment;
				inTemp[15] |= sbits;
			}
			out[cbIn - cbRemain] = temp;
			temp = 0;
			bitsCurrent = 0;
		}
	}

	return;
}

// AesCfbDecrypt 関数
// CFB を用いた Aes による複合化を行う
// IV ---------------+------------>+-------------------+------------->+--- ... -----------+ 
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
//              Plane Text 1                      Plane Text 2                       Plane Text N
VOID WINAPI AesCfbDecrypt(BYTE* in, DWORD cbIn, BYTE* IV, BYTE* Key, BYTE cbitSegment, BYTE* out)
{
	DWORD i, cbSegment, cbRemain, W[60];
	BYTE inTemp[16], MsgTemp[16], outTemp[16], * pInCurrent, temp, sbits, bitsCurrent, bitOr;

	// Segment Bits が IV (16 バイト) を超えている場合、もしくは 0 の場合終了
	if (cbitSegment > 128 || cbitSegment == 0)
	{
		return;
	}

	// 入力データサイズが Segment Bits の倍数で無い場合終了
	if ((cbIn * 8) % cbitSegment != 0)
	{
		return;
	}

	KeyExpansion(Key, W, KeyTable[CurrentAESBitLength]);

	if (cbitSegment % 8 == 0) // Segment Bits が 8 の倍数 (バイト) である場合
	{
		cbSegment = cbitSegment / 8;

		// AES-CFB による複合化
		Cipher(IV, inTemp, W); // IV の AES 暗号化
		Xor(in, inTemp, cbSegment, outTemp); // Segment Bits 分の xor
		memcpy(out, outTemp, cbSegment);// 結果を出力用バッファにコピー

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

		for (cbRemain = cbIn - cbSegment, pInCurrent = &in[cbSegment]; cbRemain > 0; cbRemain -= cbSegment, pInCurrent += cbSegment)
		{
			Cipher(inTemp, MsgTemp, W); // 前の結果から作成した入力データを AES 暗号化
			Xor(pInCurrent, MsgTemp, cbSegment, outTemp); // 結果と平文の XOR
			memcpy(&out[cbIn - cbRemain], outTemp, cbSegment); // 結果を出力用バッファにコピー

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
		}
	}
	else if (8 % cbitSegment == 0) // Segment Bits が 1, 2, 4 の場合
	{
		// AES-CFB による暗号化
		Cipher(IV, outTemp, W);
		sbits = in[0] >> (8 - cbitSegment);

		bitOr = 1;
		for (i = 1; i < cbitSegment; i++)
		{
			bitOr <<= 1;
			bitOr++;
		}

		// セグメント分入力データを左シフトし、セグメント分を挿入して入力データを作成
		for (i = 0; i < 15; i++)
		{
			inTemp[i] = IV[i] << cbitSegment;
			inTemp[i] |= IV[i + 1] >> (8 - cbitSegment);
		}
		inTemp[15] = IV[15] << cbitSegment;
		inTemp[15] |= sbits;

		bitsCurrent = cbitSegment;
		temp = sbits ^ (outTemp[0] >> (8 - cbitSegment)); // Segment Bits 分 xor
		for (cbRemain = cbIn; cbRemain > 0; cbRemain--)
		{
			while (bitsCurrent < 8)
			{
				Cipher(inTemp, outTemp, W);

				sbits = (in[cbIn - cbRemain] >> (8 - cbitSegment - bitsCurrent)) & bitOr;
				temp <<= cbitSegment;
				temp |= sbits ^ (outTemp[0] >> (8 - cbitSegment)); // Segment Bits 分 xor
				bitsCurrent += cbitSegment;

				// セグメント分入力データを左シフトし、セグメント分を挿入して入力データを作成
				for (i = 0; i < 15; i++)
				{
					inTemp[i] = inTemp[i] << cbitSegment;
					inTemp[i] |= inTemp[i + 1] >> (8 - cbitSegment);
				}
				inTemp[15] = inTemp[15] << cbitSegment;
				inTemp[15] |= sbits;
			}
			out[cbIn - cbRemain] = temp;
			temp = 0;
			bitsCurrent = 0;
		}
	}

	return;
}

// AesOfbEncryptDecrypt 関数
// OFB を用いた AES による暗号化・複合化を行う
// ・暗号化
//                  IV
//                   |             +-------------------+                  +-------------------+
//                   |             |                   |                  |                   |
//                   v             |                   v                  |                   v
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+
// Key ->|block cipher encryption| | Key ->|block cipher encryption|      | Key ->|block cipher encryption|
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+ 
//                   |             |                   |                  |                   |
//                   +-------------+                   +---------- ...  --+                   |
//                   |                                 |                                      |
// Plane Text 1 ----xor              Plane Text 1 ----xor                   Plane Text 1 ----xor
//                   |                                 |                                      |
//                   v                                 v                                      v
//              Cipher Text 1                     Cipher Text 2                         Cipher Text N
// 
// ・複合化
//                  IV
//                   |             +-------------------+                  +-------------------+
//                   |             |                   |                  |                   |
//                   v             |                   v                  |                   v
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+
// Key ->|block cipher encryption| | Key ->|block cipher encryption|      | Key ->|block cipher encryption|
//       +-----------+-----------+ |       +-----------+-----------+      |       +-----------+-----------+ 
//                   |             |                   |                  |                   |
//                   +-------------+                   +---------- ...  --+                   |
//                   |                                 |                                      |
// Cipher Text 1 ---xor              Cipher Text 1 ---xor                   Cipher Text 1 ---xor
//                   |                                 |                                      |
//                   v                                 v                                      v
//              Plane Text 1                      Plane Text 2                       Plane Text N
VOID WINAPI AesOfbEncryptDecrypt(BYTE* in, DWORD cbIn, BYTE* IV, BYTE* Key, BYTE* out)
{
	DWORD i, W[60];
	BYTE Temp1[16], Temp2[16];

	KeyExpansion(Key, W, KeyTable[CurrentAESBitLength]);

	// AES-OFB による暗号化
	Cipher(IV, Temp1, W);
	Xor(in, Temp1, 16, Temp2);
	memcpy(out, Temp2, 16);
	for (i = 16; i < cbIn; i += 16)
	{
		Cipher(Temp1, Temp2, W);
		Xor(&in[i], Temp2, 16, Temp1);
		memcpy(&out[i], Temp1, 16);
		memcpy(Temp1, Temp2, 16);
	}

	return;
}

VOID WINAPI AesCtrEncryptDecrypt(BYTE* in, DWORD cbIn, BYTE* ICV, BYTE* Key, BYTE* out)
{
	DWORD i, W[60];
	BYTE Temp[16], ICVCurrent[16];
	DWORD cbCurrent;
	ULONG64 ICVLow, ICVHigh;

	KeyExpansion(Key, W, KeyTable[CurrentAESBitLength]);

	Cipher(ICV, Temp, W);
	Xor(in, Temp, 16, out);
	memcpy(ICVCurrent, ICV, 16);
	for (cbCurrent = 16; cbCurrent < cbIn; cbCurrent += 16)
	{
		if (ICVCurrent[15] == 0xff)
		{
			ICVHigh = 0;
			for (i = 0; i < 8; i++)
			{
				ICVHigh <<= 8;
				ICVHigh += ICVCurrent[i];
			}
			ICVLow = 0;
			for (i = 8; i < 16; i++)
			{
				ICVLow <<= 8;
				ICVLow += ICVCurrent[i];
			}
			if (ICVLow == 0xffffffffffffffff)
			{
				ICVLow = 0;
				ICVHigh++;
			}
			else
			{
				ICVLow++;
			}
			for (i = 0; i < 8; i++)
			{
				ICVCurrent[7 - i] = (BYTE)(ICVHigh & 0xff);
				ICVHigh >>= 8;
			}
			for (i = 0; i < 8; i++)
			{
				ICVCurrent[15 - i] = (BYTE)(ICVLow & 0xff);
				ICVLow >>= 8;
			}
		}
		else
		{
			ICVCurrent[15]++;
		}

		Cipher(ICVCurrent, Temp, W);
		Xor(&in[cbCurrent], Temp, 16, &out[cbCurrent]);
	}

	return;
}

#define AES_MODE_ECB 1
#define AES_MODE_CBC 2
#define AES_MODE_CFB 3
#define AES_MODE_OFB 4
#define AES_MODE_CTR 5

// AesEncryptDecrypt 関数
// AES による暗号化と複合化のテスト
VOID WINAPI AesEncryptDecrypt(BYTE* in, DWORD cbIn, BYTE* IVorICV, BYTE* Key, BYTE cbitSegment, DWORD dwMode)
{
	DWORD i;
	BYTE* cipher, * out;
	BYTE Nk = KeyTable[CurrentAESBitLength];

	printf("%-21s = ", "Cipher Key");
	for (i = 0; i < (DWORD)(Nk * 4); i++)
	{
		printf("%02x", Key[i]);
		if (i % 8 == 7)
		{
			printf(" ");
		}
	}
	printf("\r\n");

	if (IVorICV != NULL)
	{
		printf("%-21s = ", "IV or ICV");
		for (i = 0; i < 16; i++)
		{
			printf("%02x", IVorICV[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");
	}

	printf("%-21s = ", "Input");
	for (i = 0; i < cbIn; i++)
	{
		printf("%02x", in[i]);
		if (i % 8 == 7)
		{
			printf(" ");
		}
	}
	printf("\r\n");

	if (cbitSegment != 0)
	{
		printf("%-21s = %u\r\n", "Segment Bits", cbitSegment);
	}

	cipher = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
	out = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);

	// AES 暗号化
	switch (dwMode)
	{
	case AES_MODE_ECB:
		AesEcbEncrypt(in, cbIn, Key, cipher);
		printf("%-21s = ", "Cipher Text (AES-ECB)");
		break;
	case AES_MODE_CBC:
		AesCbcEncrypt(in, cbIn, IVorICV, Key, cipher);
		printf("%-21s = ", "Cipher Text (AES-CBC)");
		break;
	case AES_MODE_CFB:
		AesCfbEncrypt(in, cbIn, IVorICV, Key, cbitSegment, cipher);
		printf("%-21s = ", "Cipher Text (AES-CFB)");
		break;
	case AES_MODE_OFB:
		AesOfbEncryptDecrypt(in, cbIn, IVorICV, Key, cipher);
		printf("%-21s = ", "Cipher Text (AES-OFB)");
		break;
	case AES_MODE_CTR:
		AesCtrEncryptDecrypt(in, cbIn, IVorICV, Key, cipher);
		printf("%-21s = ", "Cipher Text (AES-CTR)");
		break;
	default:
		break;
	}

	for (i = 0; i < cbIn; i++)
	{
		printf("%02x", cipher[i]);
		if (i % 8 == 7)
		{
			printf(" ");
		}
	}
	printf("\r\n");

	// AES 複合化
	switch (dwMode)
	{
	case AES_MODE_ECB:
		AesEcbDecrypt(cipher, cbIn, Key, out);
		break;
	case AES_MODE_CBC:
		AesCbcDecrypt(cipher, cbIn, IVorICV, Key, out);
		break;
	case AES_MODE_CFB:
		AesCfbDecrypt(cipher, cbIn, IVorICV, Key, cbitSegment, out);
		break;
	case AES_MODE_OFB:
		AesOfbEncryptDecrypt(cipher, cbIn, IVorICV, Key, out);
		break;
	case AES_MODE_CTR:
		AesCtrEncryptDecrypt(cipher, cbIn, IVorICV, Key, out);
		break;
	default:
		break;
	}

	printf("%-21s = ", "Output");
	for (i = 0; i < cbIn; i++)
	{
		printf("%02x", out[i]);
		if (i % 8 == 7)
		{
			printf(" ");
		}
	}
	printf("\r\n");

	HeapFree(GetProcessHeap(), 0, cipher);
	HeapFree(GetProcessHeap(), 0, out);

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
	// AES-128
	// Segment Length (CFB) = 128
	// Cipher Key = 2B7E1516 28AED2A6 ABF71588 09CF4F3C (128bit)
	// IV = 00010203 04050607 08090A0B 0C0D0E0F
	// ICV = F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF 
	// Input = 6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710 
	// Cipher Text (ECB) = 3AD77BB4 0D7A3660 A89ECAF3 2466EF97 F5D3D585 03B9699D E785895A 96FDBAAF 43B1CD7F 598ECE23 881B00E3 ED030688 7B0C785E 27E8AD3F 82232071 04725DD4
	// Cipher Text (CBC) = 7649ABAC 8119B246 CEE98E9B 12E9197D 5086CB9B 507219EE 95DB113A 917678B2 73BED6B8 E3C1743B 7116E69E 22229516 3FF1CAA1 681FAC09 120ECA30 7586E1A7
	// Cipher Text (CFB) = 3B3FD92E B72DAD20 333449F8 E83CFB4A C8A64537 A0B3A93F CDE3CDAD 9F1CE58B 26751F67 A3CBB140 B1808CF1 87A4F4DF C04B0535 7C5D1C0E EAC4C66F 9FF7F2E6
	// Cipher Text (OFB) = 3B3FD92E B72DAD20 333449F8 E83CFB4A 7789508D 16918F03 F53C52DA C54ED825 9740051E 9C5FECF6 4344F7A8 2260EDCC 304C6528 F659C778 66A510D9 C1D6AE5E
	// Cipher Text (CTR) = 874D6191 B620E326 1BEF6864 990DB6CE 9806F66B 7970FDFF 8617187B B9FFFDFF 5AE4DF3E DBD5D35E 5B4F0902 0DB03EAB 1E031DDA 2FBE03D1 792170A0 F3009CEE

	CurrentAESBitLength = AES128;
	BYTE AesExample1_SegmentLength = 128;
	BYTE AesExample1_Key[56] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
	BYTE AesExample1_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	BYTE AesExample1_ICV[16] = { 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF };
	BYTE AesExample1_Input[64] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
		0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
		0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
		0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10 };
	DWORD AesExample1_CbInput = 64;

	AesEncryptDecrypt(AesExample1_Input, AesExample1_CbInput, NULL, AesExample1_Key, 0, AES_MODE_ECB);
	printf("\r\n");
	AesEncryptDecrypt(AesExample1_Input, AesExample1_CbInput, AesExample1_IV, AesExample1_Key, 0, AES_MODE_CBC);
	printf("\r\n");
	AesEncryptDecrypt(AesExample1_Input, AesExample1_CbInput, AesExample1_IV, AesExample1_Key, AesExample1_SegmentLength, AES_MODE_CFB);
	printf("\r\n");
	AesEncryptDecrypt(AesExample1_Input, AesExample1_CbInput, AesExample1_IV, AesExample1_Key, 0, AES_MODE_OFB);
	printf("\r\n");
	AesEncryptDecrypt(AesExample1_Input, AesExample1_CbInput, AesExample1_ICV, AesExample1_Key, 0, AES_MODE_CTR);
	printf("\r\n");

	// Example 2
	// AES-192
	// Segment Length (CFB) = 128
	// Cipher Key = 8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B (192bit)
	// IV = 00010203 04050607 08090A0B 0C0D0E0F
	// ICV = F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF 
	// Input = 6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710 
	// Cipher Text (ECB) = BD334F1D 6E45F25F F712A214 571FA5CC 97410484 6D0AD3AD 7734ECB3 ECEE4EEF EF7AFD22 70E2E60A DCE0BA2F ACE6444E 9A4B41BA 738D6C72 FB166916 03C18E0E
	// Cipher Text (CBC) = 4F021DB2 43BC633D 7178183A 9FA071E8 B4D9ADA9 AD7DEDF4 E5E73876 3F69145A 571B2420 12FB7AE0 7FA9BAAC 3DF102E0 08B0E279 88598881 D920A9E6 4F5615CD
	// Cipher Text (CFB) = CDC80D6F DDF18CAB 34C25909 C99A4174 67CE7F7F 81173621 961A2B70 171D3D7A 2E1E8A1D D59B88B1 C8E60FED 1EFAC4C9 C05F9F9C A9834FA0 42AE8FBA 584B09FF
	// Cipher Text (OFB) = CDC80D6F DDF18CAB 34C25909 C99A4174 FCC28B8D 4C63837C 09E81700 C1100401 8D9A9AEA C0F6596F 559C6D4D AF59A5F2 6D9F2008 57CA6C3E 9CAC524B D9ACC92A
	// Cipher Text (CTR) = 1ABC9324 17521CA2 4F2B0459 FE7E6E0B 090339EC 0AA6FAEF D5CCC2C6 F4CE8E94 1E36B26B D1EBC670 D1BD1D66 5620ABF7 4F78A7F6 D2980958 5A97DAEC 58C6B050

	CurrentAESBitLength = AES192;
	BYTE AesExample2_SegmentLength = 128;
	BYTE AesExample2_Key[56] = { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B };
	BYTE AesExample2_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	BYTE AesExample2_ICV[16] = { 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF };
	BYTE AesExample2_Input[64] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
		0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
		0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
		0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10 };
	DWORD AesExample2_CbInput = 64;

	AesEncryptDecrypt(AesExample2_Input, AesExample2_CbInput, NULL, AesExample2_Key, 0, AES_MODE_ECB);
	printf("\r\n");
	AesEncryptDecrypt(AesExample2_Input, AesExample2_CbInput, AesExample2_IV, AesExample2_Key, 0, AES_MODE_CBC);
	printf("\r\n");
	AesEncryptDecrypt(AesExample2_Input, AesExample2_CbInput, AesExample2_IV, AesExample2_Key, AesExample2_SegmentLength, AES_MODE_CFB);
	printf("\r\n");
	AesEncryptDecrypt(AesExample2_Input, AesExample2_CbInput, AesExample2_IV, AesExample2_Key, 0, AES_MODE_OFB);
	printf("\r\n");
	AesEncryptDecrypt(AesExample2_Input, AesExample2_CbInput, AesExample2_ICV, AesExample2_Key, 0, AES_MODE_CTR);
	printf("\r\n");

	// Example 3
	// AES-256
	// Segment Length (CFB) = 128
	// Cipher Key = 603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4 (256bit)
	// IV = 00010203 04050607 08090A0B 0C0D0E0F
	// ICV = F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF 
	// Input = 6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51 30C81C46 A35CE411 E5FBC119 1A0A52EF F69F2445 DF4F9B17 AD2B417B E66C3710 
	// Cipher Text (ECB) = F3EED1BD B5D2A03C 064B5A7E 3DB181F8 591CCB10 D410ED26 DC5BA74A 31362870 B6ED21B9 9CA6F4F9 F153E7B1 BEAFED1D 23304B7A 39F9F3FF 067D8D8F 9E24ECC7
	// Cipher Text (CBC) = F58C4C04 D6E5F1BA 779EABFB 5F7BFBD6 9CFC4E96 7EDB808D 679F777B C6702C7D 39F23369 A9D9BACF A530E263 04231461 B2EB05E2 C39BE9FC DA6C1907 8C6A9D1B
	// Cipher Text (CFB) = DC7E84BF DA79164B 7ECD8486 985D3860 39FFED14 3B28B1C8 32113C63 31E5407B DF101324 15E54B92 A13ED0A8 267AE2F9 75A38574 1AB9CEF8 2031623D 55B1E471
	// Cipher Text (OFB) = DC7E84BF DA79164B 7ECD8486 985D3860 4FEBDC67 40D20B3A C88F6AD8 2A4FB08D 71AB47A0 86E86EED F39D1C5B BA97C408 0126141D 67F37BE8 538F5A8B E740E484
	// Cipher Text (CTR) = 601EC313 775789A5 B7A7F504 BBF3D228 F443E3CA 4D62B59A CA84E990 CACAF5C5 2B0930DA A23DE94C E87017BA 2D84988D DFC9C58D B67AADA6 13C2DD08 457941A6

	CurrentAESBitLength = AES256;
	BYTE AesExample3_SegmentLength = 128;
	BYTE AesExample3_Key[56] = { 0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4 };
	BYTE AesExample3_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	BYTE AesExample3_ICV[16] = { 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF };
	BYTE AesExample3_Input[64] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
		0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C, 0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51,
		0x30, 0xC8, 0x1C, 0x46, 0xA3, 0x5C, 0xE4, 0x11, 0xE5, 0xFB, 0xC1, 0x19, 0x1A, 0x0A, 0x52, 0xEF,
		0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17, 0xAD, 0x2B, 0x41, 0x7B, 0xE6, 0x6C, 0x37, 0x10 };
	DWORD AesExample3_CbInput = 64;

	AesEncryptDecrypt(AesExample3_Input, AesExample3_CbInput, NULL, AesExample3_Key, 0, AES_MODE_ECB);
	printf("\r\n");
	AesEncryptDecrypt(AesExample3_Input, AesExample3_CbInput, AesExample3_IV, AesExample3_Key, 0, AES_MODE_CBC);
	printf("\r\n");
	AesEncryptDecrypt(AesExample3_Input, AesExample3_CbInput, AesExample3_IV, AesExample3_Key, AesExample3_SegmentLength, AES_MODE_CFB);
	printf("\r\n");
	AesEncryptDecrypt(AesExample3_Input, AesExample3_CbInput, AesExample3_IV, AesExample3_Key, 0, AES_MODE_OFB);
	printf("\r\n");
	AesEncryptDecrypt(AesExample3_Input, AesExample3_CbInput, AesExample3_ICV, AesExample3_Key, 0, AES_MODE_CTR);
	printf("\r\n");

	// Example 4
	// AES-128, AES-192, AES-256
	// Segment Length (CFB) = 8
	// Cipher Key 1 = 2B7E1516 28AED2A6 ABF71588 09CF4F3C (128bit)
	// Cipher Key 2 = 8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B (192bit)
	// Cipher Key 3 = 603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4 (256bit)
	// Input = 6BC1BEE2 2E409F96 E93D7E11 7393172A 
	// Cipher Text 1 = 3B79424C 9C0DD436 BACE9E0E D4586A4F
	// Cipher Text 2 = CDA2521E F0A905CA 44CD057C BF0D47A0
	// Cipher Text 3 = DC1F1A85 20A64DB5 5FCC8AC5 54844E88
	BYTE AesExample4_SegmentLength = 8;
	BYTE AesExample4_Key1[56] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
	BYTE AesExample4_Key2[56] = { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B };
	BYTE AesExample4_Key3[56] = { 0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4 };
	BYTE AesExample4_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	BYTE AesExample4_Input[16] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };
	DWORD AesExample4_CbInput = 16;

	CurrentAESBitLength = AES128;
	AesEncryptDecrypt(AesExample4_Input, AesExample4_CbInput, AesExample4_IV, AesExample4_Key1, AesExample4_SegmentLength, AES_MODE_CFB);
	printf("\r\n");

	CurrentAESBitLength = AES192;
	AesEncryptDecrypt(AesExample4_Input, AesExample4_CbInput, AesExample4_IV, AesExample4_Key2, AesExample4_SegmentLength, AES_MODE_CFB);
	printf("\r\n");

	CurrentAESBitLength = AES256;
	AesEncryptDecrypt(AesExample4_Input, AesExample4_CbInput, AesExample4_IV, AesExample4_Key3, AesExample4_SegmentLength, AES_MODE_CFB);
	printf("\r\n");

	// Example 5
	// AES-128, AES-192, AES-256
	// Segment Length (CFB) = 1
	// Cipher Key 1 = 2B7E1516 28AED2A6 ABF71588 09CF4F3C (128bit)
	// Cipher Key 2 = 8E73B0F7 DA0E6452 C810F32B 809079E5 62F8EAD2 522C6B7B (192bit)
	// Cipher Key 3 = 603DEB10 15CA71BE 2B73AEF0 857D7781 1F352C07 3B6108D7 2D9810A3 0914DFF4 (256bit)
	// Input = 6BC1
	// Cipher Text 1 = 68b3 (AES_ModesA_All.pdf 記載の 69C8 は誤り)
	// Cipher Text 2 = 9359 (AES_ModesA_All.pdf 記載の 9776 は誤り)
	// Cipher Text 3 = 9029 (AES_ModesA_All.pdf 記載の 93D0 は誤り)
	BYTE AesExample5_SegmentLength = 1;
	BYTE AesExample5_Key1[56] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
	BYTE AesExample5_Key2[56] = { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5, 0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B };
	BYTE AesExample5_Key3[56] = { 0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81, 0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4 };
	BYTE AesExample5_IV[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	BYTE AesExample5_Input[2] = { 0x6B, 0xC1 };
	DWORD AesExample5_CbInput = 2;

	CurrentAESBitLength = AES128;
	AesEncryptDecrypt(AesExample5_Input, AesExample5_CbInput, AesExample5_IV, AesExample5_Key1, AesExample5_SegmentLength, AES_MODE_CFB);
	printf("\r\n");

	CurrentAESBitLength = AES192;
	AesEncryptDecrypt(AesExample5_Input, AesExample5_CbInput, AesExample5_IV, AesExample5_Key2, AesExample5_SegmentLength, AES_MODE_CFB);
	printf("\r\n");

	CurrentAESBitLength = AES256;
	AesEncryptDecrypt(AesExample5_Input, AesExample5_CbInput, AesExample5_IV, AesExample5_Key3, AesExample5_SegmentLength, AES_MODE_CFB);
	printf("\r\n");

	return 0;
}