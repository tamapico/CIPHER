#include <Windows.h>
#include <stdio.h>

// DES (Data Encryption Standard) による暗号化

// 参考
// https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-67r2.pdf
// https://csrc.nist.gov/CSRC/media/Publications/fips/81/archive/1980-12-02/documents/fips81.pdf
// https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=910079
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_Core.pdf
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TDES_ModesA_All.pdf

// PC1 : Permuted Choice 1
BYTE PC1[56] =
{
	57, 49, 41, 33, 25, 17, 9, 1,
	58, 50, 42, 34, 26, 18, 10, 2,
	59, 51, 43, 35, 27, 19, 11, 3,
	60, 52, 44, 36, 63, 55, 47, 39,
	31, 23, 15, 7, 62, 54, 46, 38,
	30, 22, 14, 6, 61, 53, 45, 37,
	29, 21, 13, 5, 28, 20, 12, 4
};

// PC2 : Permuted Choice 2
BYTE PC2[48] =
{
	14, 17, 11, 24, 1, 5, 3, 28,
	15, 6, 21, 10, 23, 19, 12, 4,
	26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40,
	51, 45, 33, 48, 44, 49, 39, 56,
	34, 53, 46, 42, 50, 36, 29, 32
};

BYTE NumLeftShifts[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

// IP : initial permutation 
BYTE IP[64] =
{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7
};

// IP^-1 : inverse initial permutation
BYTE InvIP[64] =
{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25
};

BYTE E[48] =
{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1
};

BYTE S[8][64] =
{
	{
		// S1
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13
	},
	{
		// S2
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9
	},
	{
		// S3
		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12
	},
	{
		// S4
		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14
	},
	{
		// S5
		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3
	},
	{
		// S6
		12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13
	},
	{
		// S7
		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12
	},
	{
		// S8
		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11
	}
};

BYTE P[] =
{
	16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25
};

// Permutation 関数
// Permutation (転置) を行うための関数
// 転置とは、ビット位置に当たる数値を持つ N バイトのテーブルを用いて
// 入力データを別のバイト列に置き換える操作を言う
// 入力データの最も左のビットの位置を 1 とし、右に 2, 3, 4 ... と増えていく
// この操作を行うに当たって以下の条件がある
// 1.cbTable は 8 の倍数でなければならない
// 2.出力用バッファ out のサイズ (バイト数) は、 cbTable / 8 と一致しなければならない
// 3.入力用バッファ in のサイズ (バイト数) は、table 内の最大値 / 8 を越えてはならない
VOID WINAPI Permutation(BYTE* in, BYTE* table, DWORD cbTable, BYTE* out)
{
	BYTE byteTemp, bitTemp, bitIn, byteIn, bitOut, byteOut, i, j;

	for (i = 0; i < cbTable / 8; i++)
	{
		byteOut = 0;
		for (j = 0; j < 8; j++)
		{
			for (j = 0; j < 8; j++)
			{
				// 平文 8 バイト中の何バイト目か (0 ～ cbTable / 8)
				byteTemp = (table[i * 8 + j] - 1) / 8;
				// 1 バイト中の何ビット目か (0～7)
				bitTemp = (table[i * 8 + j] - 1) % 8;
				byteIn = in[byteTemp];
				bitIn = (byteIn >> (7 - bitTemp)) & 1;

				bitOut = bitIn << (7 - j);
				byteOut |= bitOut;
			}
			// 結果を保存
			out[i] = byteOut;
		}
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

// DesEncrypt 関数
// DES による暗号化を行う。DES による暗号化は以下の手順を経て行われる
// 1.入力データとして 64 ビットの平文と、64 ビットの暗号化鍵を受け取る
// 2.64 ビットの暗号化鍵を元に Permuted Choice 1 を行い 56 ビットの鍵 K0 を生成する
// 3.K0 のデータを 28 ビットのデータ C0, D0 の 2 つに分割する
// 4.C0, D0 のそれぞれを左ローテート (仕様書では左シフトと記載されているが、実際は左ローテート) して C1, D1 を作成する
// 5.C1, D1 のデータを元に Permuted Choice 2 を行い、48 ビットの鍵 K1 を生成する
// 6.C1, D1 ～ C16, D16 について 4. 及び 5. の処理を繰り返し K1～K16を作成する
// 7.平文について Initial Permutation (IP) と呼ばれる初期転置を行う
// 8.初期転置を行った結果を 32 ビットのデータ L0, R0 の 2 つに分割する
// 9.R0 を 32 ビットから 48 ビットに拡張する
// 10.R0 をそのまま L1 とする
// 11 R0 を 48 ビットに拡張したものと K1 を入力データとして f 関数を呼び出し、その結果と L0 の論理積を R1 とする
// 12.L0, R0 ～ L15, R15 について 9. ～ 11. の処理を繰り返し L1, R1 ～ L16, R16 を作成する
// 13.R16, L16 (R16 が左で L16 が右) を元に Inverse Initial Permutation (最終転置) を行って、64 ビットの暗号化文を取得する
// 
// これを図にすると以下のようになる
// +---------------------------------+           +---------------------------------+
// | Plain Text (64 bits)            |           | Original Key (64 bits)          |
// +----------------+----------------+           +----------------+----------------+
//                  | Initial Permutation (IP)                    | Permuted Choice 1
//                  |                            +----------------+----------------+  +----------------+----------------+
// +----------------+----------------+           | Permuted Key K0 (56 bits)       +->+ C0 (上位28bits)| D0 (上位28bits)|
// | L0 (上位32bits)| R0 (下位32bits)|           +---------------------------------+  +--------+-------+-------+--------+
// +--------+-------+-------+--------+                                                         | 左ローテート  | 左ローテート
//          |               |                    +---------------------------------+  +--------+-------+-------+--------+
//          | +-------------+                    | Permuted Key K1 (48 bits)       +<-+ C1 (28 bits)   | D1 (28 bits)   |
//          |/      +-------+--------+           +----------------+----------------+  +--------+-------+-------+--------+
//         /|       | Expansion      |                            |         Permuted Choice 2  | 左ローテート  | 左ローテート            
//        / |       +-------+--------+     +----------------------+                            |               |
//       /  |               |              |     +---------------------------------+  +--------+-------+-------+--------+
//      /   |       +-------+--------+     |     | Permuted Key K2 (48 bits)       +<-+ C2 (28 bits)   | D2 (28 bits)   |
//      |   |       | f              +-----+     +----------------+----------------+  +--------+-------+-------+--------+
//      |   |       +-------+--------+                            |         Permuted Choice 2  | 左ローテート  | 左ローテート 
//      |  xor--------------+                                     :                            :               :
//      |   |                                                     :                            :               :
//      |   +---------------+
//      |                   |
// +----+-----------+-------+--------+
// | L1 (32bits)    | R1 (32bits)    |
// +--------+-------+-------+--------+
//          |               |
//          :               :
// +--------+-------+-------+--------+
// | L16 (32bits)   | R16 (32bits)   |
// +--------+-------+-------+--------+
//          |               |
//          +-------+-------+
//                  | Inverse Initial Permutation
// +---------------------------------+
// | Cipher Text (64 bits)           |
// +---------------------------------+
// 
VOID WINAPI DesEncrypt(BYTE* in, BYTE* OriginalKey, BYTE* out)
{
	BYTE i, j, temp[8];

	// Key Schedule 1 (KS1)
	// 与えられたオリジナルの鍵を元に 56 ビットの鍵 K0 を 1 個と、 48 ビットの鍵 16 個を作成する
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// |01|02|03|04|05|06|07|08|09|10|11|12|13|14|15|16|17|18|19|20|21|22|23|24|25|26|27|28|29|30|31|32|33|34|35|36|37|38|39|40|41|42|43|44|45|46|47|48|49|50|51|52|53|54|55|56|
	// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	// | Permuted Key (56 bits)                                                                                                                                                |
	// +-----------------------------------------------------------------------------------+-----------------------------------------------------------------------------------+
	// | C0 (28 bits)                                                                      | D0 (28 bits)                                                                      |
	// +-----------------------------------------------------------------------------------+-----------------------------------------------------------------------------------+
	// C0, D0 についてそれぞれ 1 ビットローテートして C1, D1 を作成する
	//  +---------------------------------------------------------------------------------+  +--------------------------------------------------------------------------------+ 
	//  |                                                                                 |  |                                                                                |
	//  |                                                                                 v  |                                                                                v
	// +-----------------------------------------------------------------------------------+-----------------------------------------------------------------------------------+
	// | C1 (28 bits)                                                                      | D1 (28 bits)                                                                      |
	// +-----------------------------------------------------------------------------------+-----------------------------------------------------------------------------------+
	// 同じように C2, D2 については C1, D1 をそれぞれビットローテートして作成する
	// ローテートするビット数は、それぞれ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
	BYTE C[17][4], D[17][4], K[17][7], KTemp[7];

	BYTE inIP[8], L[17][4], R[17][4], RExp[17][6], RXorK[17][6], Row, Column, SRet[4], PRet[4];

	// Permuted Choice 1
	Permutation(OriginalKey, PC1, 56, K[0]);

	// C0 : 56 ビットに縮小転置した K の上位 28 ビット
	memcpy(C[0], K[0], 4);
	C[0][3] &= 0xf0;

	// D0 : 56 ビットに縮小転置した K の下位 28 ビット
	memcpy(D[0], &K[0][3], 4);
	D[0][0] &= 0xf;

	for (i = 1; i < 17; i++)
	{
		// Cn は Cn-1 を NumLeftShifts[n - 1] ビット左ローテートしたもの
		for (j = 0; j < 4; j++)
		{
			C[i][j] = C[i - 1][j] << NumLeftShifts[i - 1];
			if (j < 3)
			{
				C[i][j] |= C[i - 1][j + 1] >> (8 - NumLeftShifts[i - 1]);
			}
		}
		C[i][3] |= (C[i - 1][0] >> (8 - NumLeftShifts[i - 1])) << 4;

		// Dn は Dn-1 を NumLeftShifts[n - 1] ビット左ローテートしたもの
		for (j = 0; j < 4; j++)
		{
			D[i][j] = D[i - 1][j] << NumLeftShifts[i - 1];
			if (j < 3)
			{
				D[i][j] |= D[i - 1][j + 1] >> (8 - NumLeftShifts[i - 1]);
			}
		}
		D[i][3] |= D[i - 1][0] >> (4 - NumLeftShifts[i - 1]);
		D[i][0] &= 0xf;

		// Cn と Dn から Kn を作成する

		memcpy(KTemp, C[i], 3);
		memcpy(&KTemp[4], &D[i][1], 3);
		KTemp[3] = C[i][3] | D[i][0];

		// Permuted Choice 2
		Permutation(KTemp, PC2, 48, K[i]);
		K[i][6] = 0;
	}

	// Initial Permutation
	Permutation(in, IP, 64, inIP);

	// 上位 32bit
	memcpy(L[0], inIP, 4);

	// 下位 32bit
	memcpy(R[0], &inIP[4], 4);

	for (i = 0; i < 16; i++)
	{
		// f : Feistel Structure 
		// Expansion
		Permutation(R[i], E, 48, RExp[i]);

		// Xor
		Xor(RExp[i], K[i + 1], 6, RXorK[i]);

		// S 関数
		// 48 ビットを 6 ビットずつの 8 個に分割し、bit1, bit6 の 2 進数 (00 ～ 11 の4通り) を Row とする
		// bit2 ～ bit5 の 2 進数 (0000 ～ 1111 の 16 通り) を Column とする
		// これを S1 ～ S8 のそれぞれのテーブルにあてはめ、4 ビットの 2進数値 (0000 ～ 1111 の 16 通り) B1 ～ B8 の 32 ビットを取得する
		ZeroMemory(SRet, 4);
		for (j = 0; j < 8; j++)
		{
			Row = (RXorK[i][(j * 6) / 8] >> (7 - (j * 6) % 8)) & 1;
			Row <<= 1;
			Row |= (RXorK[i][(j * 6 + 5) / 8] >> (7 - (j * 6 + 5) % 8)) & 1;

			Column = (RXorK[i][(j * 6 + 1) / 8] >> (7 - (j * 6 + 1) % 8)) & 1;
			Column <<= 1;
			Column |= (RXorK[i][(j * 6 + 2) / 8] >> (7 - (j * 6 + 2) % 8)) & 1;
			Column <<= 1;
			Column |= (RXorK[i][(j * 6 + 3) / 8] >> (7 - (j * 6 + 3) % 8)) & 1;
			Column <<= 1;
			Column |= (RXorK[i][(j * 6 + 4) / 8] >> (7 - (j * 6 + 4) % 8)) & 1;

			SRet[j / 2] <<= 4;
			SRet[j / 2] |= S[j][Row * 16 + Column];
		}

		// P 関数
		// S 関数によって得られた結果を P テーブルにあてはめ 32 ビット→32 ビットの転置を行う
		Permutation(SRet, P, 32, PRet);

		// Ln と P 関数によって得られた結果を xor して Rn+1 を得る
		Xor(L[i], PRet, 4, R[i + 1]);

		// Rn はそのまま Ln+1 となる
		memcpy(L[i + 1], R[i], 4);
	}

	memcpy(temp, R[16], 4);
	memcpy(&temp[4], L[16], 4);

	// Final Permutation
	Permutation(temp, InvIP, 64, out);

	return;
}

// DesDecrypt 関数
// Des によって暗号化された文を複合化する。以下の順序で処理を行う
// 入力データを 64 ビット毎に分割して処理を行う
// 1.入力データとして 64 ビットの平文と、64 ビットの暗号化鍵を受け取る
// 2.64 ビットの暗号化鍵を元に Permuted Choice 1 を行い 56 ビットの鍵 K0 を生成する
// 3.K0 のデータを 28 ビットのデータ C0, D0 の 2 つに分割する
// 4.C0, D0 のそれぞれを左ローテート (仕様書では左シフトと記載されているが、実際は左ローテート) して C1, D1 を作成する
// 5.C1, D1 のデータを元に Permuted Choice 2 を行い、48 ビットの鍵 K1 を生成する
// 6.C1, D1 ～ C16, D16 について 4. 及び 5. の処理を繰り返し K1～K16を作成する
// 7.平文について Initial Permutation (IP) と呼ばれる初期転置を行う
// 8.初期転置を行った結果を 32 ビットのデータ L0, R0 の 2 つに分割する
// 9.n が 0 より大きい場合 L0 と R0 を入れ替える
// 10.R0 を R1 とする
// 11.R0 を 32 ビットから 48 ビットに拡張する
// 12 R0 を 48 ビットに拡張したものと K16 を入力データとして f 関数を呼び出し、その結果と L0 の排他的論理和を L1 とする
// 13.L0, R0 ～ L15, R15 について 9. ～ 12. の処理を繰り返し L1, R1 ～ L16, R16 を作成する
// 13.L16, R16 を元に Inverse Initial Permutation (最終転置) を行って、64 ビットの暗号化文を取得する
// 
VOID WINAPI DesDecrypt(BYTE* in, BYTE* OriginalKey, BYTE* out)
{
	BYTE i, j, temp[8];

	// Key Schedule 1 (KS1)
	BYTE C[17][4], D[17][4], K[17][7], KTemp[7];

	BYTE inIP[8], L[17][4], R[17][4], RExp[17][6], RXorK[17][6], Row, Column, SRet[4], PRet[4];

	// Permuted Choice 1
	Permutation(OriginalKey, PC1, 56, K[0]);

	// C0 : 56 ビットに縮小転置した K の上位 28 ビット
	memcpy(C[0], K[0], 4);
	C[0][3] &= 0xf0;

	// D0 : 56 ビットに縮小転置した K の下位 28 ビット
	memcpy(D[0], &K[0][3], 4);
	D[0][0] &= 0xf;

	for (i = 1; i < 17; i++)
	{
		// Cn は Cn-1 を NumLeftShifts[n - 1] ビット左ローテートしたもの
		for (j = 0; j < 4; j++)
		{
			C[i][j] = C[i - 1][j] << NumLeftShifts[i - 1];
			if (j < 3)
			{
				C[i][j] |= C[i - 1][j + 1] >> (8 - NumLeftShifts[i - 1]);
			}
		}
		C[i][3] |= (C[i - 1][0] >> (8 - NumLeftShifts[i - 1])) << 4;

		// Dn は Dn-1 を NumLeftShifts[n - 1] ビット左ローテートしたもの
		for (j = 0; j < 4; j++)
		{
			D[i][j] = D[i - 1][j] << NumLeftShifts[i - 1];
			if (j < 3)
			{
				D[i][j] |= D[i - 1][j + 1] >> (8 - NumLeftShifts[i - 1]);
			}
		}
		D[i][3] |= D[i - 1][0] >> (4 - NumLeftShifts[i - 1]);
		D[i][0] &= 0xf;

		// Cn と Dn から Kn を作成する

		memcpy(KTemp, C[i], 3);
		memcpy(&KTemp[4], &D[i][1], 3);
		KTemp[3] = C[i][3] | D[i][0];

		// Permuted Choice 2
		Permutation(KTemp, PC2, 48, K[i]);
		K[i][6] = 0;
	}

	// Initial Permutation
	Permutation(in, IP, 64, inIP);

	// 上位 32bit
	memcpy(L[0], inIP, 4);

	// 下位 32bit
	memcpy(R[0], &inIP[4], 4);

	for (i = 0; i < 16; i++)
	{
		if (i > 0)
		{
			memcpy(R[i], L[i], 4);
			memcpy(L[i], R[i - 1], 4);
		}

		// f : Feistel Structure 
		// Expansion
		Permutation(R[i], E, 48, RExp[i]);

		// Xor
		Xor(RExp[i], K[16 - i], 6, RXorK[i]);

		// S 関数
		// 48 ビットを 6 ビットずつの 8 個に分割し、bit1, bit6 の 2 進数 (00 ～ 11 の4通り) を Row とする
		// bit2 ～ bit5 の 2 進数 (0000 ～ 1111 の 16 通り) を Column とする
		// これを S1 ～ S8 のそれぞれのテーブルにあてはめ、4 ビットの 2進数値 (0000 ～ 1111 の 16 通り) B1 ～ B8 の 32 ビットを取得する
		ZeroMemory(SRet, 4);
		for (j = 0; j < 8; j++)
		{
			Row = (RXorK[i][(j * 6) / 8] >> (7 - (j * 6) % 8)) & 1;
			Row <<= 1;
			Row |= (RXorK[i][(j * 6 + 5) / 8] >> (7 - (j * 6 + 5) % 8)) & 1;

			Column = (RXorK[i][(j * 6 + 1) / 8] >> (7 - (j * 6 + 1) % 8)) & 1;
			Column <<= 1;
			Column |= (RXorK[i][(j * 6 + 2) / 8] >> (7 - (j * 6 + 2) % 8)) & 1;
			Column <<= 1;
			Column |= (RXorK[i][(j * 6 + 3) / 8] >> (7 - (j * 6 + 3) % 8)) & 1;
			Column <<= 1;
			Column |= (RXorK[i][(j * 6 + 4) / 8] >> (7 - (j * 6 + 4) % 8)) & 1;

			SRet[j / 2] <<= 4;
			SRet[j / 2] |= S[j][Row * 16 + Column];
		}

		// P 関数
		// S 関数によって得られた結果を P テーブルにあてはめ 32 ビット→32 ビットの転置を行う
		Permutation(SRet, P, 32, PRet);

		// Ln と P 関数によって得られた結果を xor して Ln+1 を得る
		Xor(L[i], PRet, 4, L[i + 1]);

		// Rn はそのまま Rn+1 となる
		memcpy(R[i + 1], R[i], 4);
	}

	memcpy(temp, L[16], 4);
	memcpy(&temp[4], R[16], 4);

	// Final Permutation
	Permutation(temp, InvIP, 64, out);

	return;
}

VOID WINAPI DesEcbEncryptDecrypt(BYTE* in, DWORD cbIn, BYTE* OriginalKey, BYTE* out)
{
	DWORD cbCurrent;

	DesEncrypt(in, OriginalKey, out);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		DesEncrypt(&in[cbCurrent], OriginalKey, &out[cbCurrent]);
	}

	return;
}


VOID WINAPI DesCbcEncrypt(BYTE* in, DWORD cbIn, BYTE* OriginalKey, BYTE* IV, BYTE* out)
{
	BYTE inTemp[8];
	DWORD cbCurrent;

	Xor(in, IV, 8, inTemp);
	DesEncrypt(inTemp, OriginalKey, out);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		Xor(&in[cbCurrent], &out[cbCurrent - 8], 8, inTemp);
		DesEncrypt(inTemp, OriginalKey, &out[cbCurrent]);
	}

	return;
}

VOID WINAPI DesCbcDecrypt(BYTE* in, DWORD cbIn, BYTE* OriginalKey, BYTE* IV, BYTE* out)
{
	BYTE outTemp[8];
	DWORD cbCurrent;

	DesDecrypt(in, OriginalKey, outTemp);
	Xor(outTemp, IV, 8, out);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		DesDecrypt(&in[cbCurrent], OriginalKey, outTemp);
		Xor(outTemp, &in[cbCurrent - 8], 8, &out[cbCurrent]);
	}

	return;
}

VOID WINAPI DesCfbEncrypt(BYTE* in, DWORD cbIn, BYTE* OriginalKey, BYTE* IV, BYTE* out)
{
	BYTE outTemp[8];
	DWORD cbCurrent;

	DesEncrypt(IV, OriginalKey, outTemp);
	Xor(in, outTemp, 8, out);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		DesEncrypt(&out[cbCurrent - 8], OriginalKey, outTemp);
		Xor(&in[cbCurrent], outTemp, 8, &out[cbCurrent]);
	}

	return;
}

VOID WINAPI DesCfbDecrypt(BYTE* in, DWORD cbIn, BYTE* OriginalKey, BYTE* IV, BYTE* out)
{
	BYTE outTemp[8];
	DWORD cbCurrent;

	DesEncrypt(IV, OriginalKey, outTemp);
	Xor(in, outTemp, 8, out);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		DesEncrypt(&in[cbCurrent - 8], OriginalKey, outTemp);
		Xor(&in[cbCurrent], outTemp, 8, &out[cbCurrent]);
	}

	return;
}

VOID WINAPI DesOfbEncryptDecrypt(BYTE* in, DWORD cbIn, BYTE* OriginalKey, BYTE* IV, BYTE* out)
{
	BYTE Temp1[8], Temp2[8];
	DWORD cbCurrent;

	DesEncrypt(IV, OriginalKey, Temp2);
	Xor(in, Temp2, 8, out);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		DesEncrypt(Temp2, OriginalKey, Temp1);
		Xor(&in[cbCurrent], Temp1, 8, &out[cbCurrent]);
	}

	return;
}

VOID WINAPI TdeaEncrypt(BYTE* in, BYTE* Key1, BYTE* Key2, BYTE* Key3, BYTE* out)
{
	BYTE Temp1[8], Temp2[8];

	DesEncrypt(in, Key1, Temp2);
	DesDecrypt(Temp2, Key2, Temp1);
	DesEncrypt(Temp1, Key3, out);

	return;
}

VOID WINAPI TdeaDecrypt(BYTE* in, BYTE* Key1, BYTE* Key2, BYTE* Key3, BYTE* out)
{
	BYTE Temp1[8], Temp2[8];

	DesDecrypt(in, Key3, Temp2);
	DesEncrypt(Temp2, Key2, Temp1);
	DesDecrypt(Temp1, Key1, out);

	return;
}

VOID WINAPI TdeaEcbEncrypt(BYTE* in, DWORD cbIn, BYTE* Key1, BYTE* Key2, BYTE* Key3, BYTE* out)
{
	BYTE Temp1[8], Temp2[8];
	DWORD cbCurrent;

	DesEncrypt(in, Key1, Temp2);
	DesDecrypt(Temp2, Key2, Temp1);
	DesEncrypt(Temp1, Key3, out);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		DesEncrypt(&in[cbCurrent], Key1, Temp2);
		DesDecrypt(Temp2, Key2, Temp1);
		DesEncrypt(Temp1, Key3, &out[cbCurrent]);
	}

	return;
}

VOID WINAPI TdeaEcbDecrypt(BYTE* in, DWORD cbIn, BYTE* Key1, BYTE* Key2, BYTE* Key3, BYTE* out)
{
	BYTE Temp1[8], Temp2[8];
	DWORD cbCurrent;

	DesDecrypt(in, Key3, Temp2);
	DesEncrypt(Temp2, Key2, Temp1);
	DesDecrypt(Temp1, Key1, out);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		DesDecrypt(&in[cbCurrent], Key3, Temp2);
		DesEncrypt(Temp2, Key2, Temp1);
		DesDecrypt(Temp1, Key1, &out[cbCurrent]);
	}

	return;
}

VOID WINAPI TdeaCbcEncrypt(BYTE* in, DWORD cbIn, BYTE* Key1, BYTE* Key2, BYTE* Key3, BYTE* IV, BYTE* out)
{
	BYTE Temp1[8], Temp2[8];
	DWORD cbCurrent;

	Xor(in, IV, 8, Temp1);
	DesEncrypt(Temp1, Key1, Temp2);
	DesDecrypt(Temp2, Key2, Temp1);
	DesEncrypt(Temp1, Key3, Temp2);
	memcpy(out, Temp2, 8);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		Xor(Temp2, &in[cbCurrent], 8, Temp1);
		DesEncrypt(Temp1, Key1, Temp2);
		DesDecrypt(Temp2, Key2, Temp1);
		DesEncrypt(Temp1, Key3, Temp2);
		memcpy(&out[cbCurrent], Temp2, 8);
	}

	return;
}

VOID WINAPI TdeaCbcDecrypt(BYTE* in, DWORD cbIn, BYTE* Key1, BYTE* Key2, BYTE* Key3, BYTE* IV, BYTE* out)
{
	BYTE Temp1[8], Temp2[8];
	DWORD cbCurrent;

	DesDecrypt(in, Key3, Temp2);
	DesEncrypt(Temp2, Key2, Temp1);
	DesDecrypt(Temp1, Key1, Temp2);
	Xor(Temp2, IV, 8, out);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		DesDecrypt(&in[cbCurrent], Key3, Temp2);
		DesEncrypt(Temp2, Key2, Temp1);
		DesDecrypt(Temp1, Key1, Temp2);
		Xor(Temp2, &in[cbCurrent - 8], 8, &out[cbCurrent]);
	}

	return;
}

VOID WINAPI TdeaCfbEncrypt(BYTE* in, DWORD cbIn, BYTE* Key1, BYTE* Key2, BYTE* Key3, BYTE* IV, BYTE* out)
{
	BYTE Temp1[8], Temp2[8];
	DWORD cbCurrent;

	DesEncrypt(IV, Key1, Temp1);
	DesDecrypt(Temp1, Key2, Temp2);
	DesEncrypt(Temp2, Key3, Temp1);
	Xor(in, Temp1, 8, Temp2);
	memcpy(out, Temp2, 8);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		DesEncrypt(Temp2, Key1, Temp1);
		DesDecrypt(Temp1, Key2, Temp2);
		DesEncrypt(Temp2, Key3, Temp1);
		Xor(&in[cbCurrent], Temp1, 8, Temp2);
		memcpy(&out[cbCurrent], Temp2, 8);
	}

	return;
}

VOID WINAPI TdeaCfbDecrypt(BYTE* in, DWORD cbIn, BYTE* Key1, BYTE* Key2, BYTE* Key3, BYTE* IV, BYTE* out)
{
	BYTE Temp1[8], Temp2[8];
	DWORD cbCurrent;

	DesEncrypt(IV, Key1, Temp1);
	DesDecrypt(Temp1, Key2, Temp2);
	DesEncrypt(Temp2, Key3, Temp1);
	Xor(in, Temp1, 8, out);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		DesEncrypt(&in[cbCurrent - 8], Key1, Temp1);
		DesDecrypt(Temp1, Key2, Temp2);
		DesEncrypt(Temp2, Key3, Temp1);
		Xor(&in[cbCurrent], Temp1, 8, &out[cbCurrent]);
	}

	return;
}

VOID WINAPI TdeaOfbEncryptDecrypt(BYTE* in, DWORD cbIn, BYTE* Key1, BYTE* Key2, BYTE* Key3, BYTE* IV, BYTE* out)
{
	BYTE Temp1[8], Temp2[8];
	DWORD cbCurrent;

	DesEncrypt(IV, Key1, Temp1);
	DesDecrypt(Temp1, Key2, Temp2);
	DesEncrypt(Temp2, Key3, Temp1);
	Xor(in, Temp1, 8, out);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		DesEncrypt(Temp1, Key1, Temp2);
		DesDecrypt(Temp2, Key2, Temp1);
		DesEncrypt(Temp1, Key3, Temp2);
		Xor(&in[cbCurrent], Temp2, 8, &out[cbCurrent]);
		memcpy(Temp1, Temp2, 8);
	}

	return;
}

VOID WINAPI TdeaCtrEncryptDecrypt(BYTE* in, DWORD cbIn, BYTE* Key1, BYTE* Key2, BYTE* Key3, BYTE* ICV, BYTE* out)
{
	BYTE Temp1[8], Temp2[8], ICVCurrent[8], i;
	DWORD cbCurrent;
	ULONG64 ICVTemp;

	DesEncrypt(ICV, Key1, Temp1);
	DesDecrypt(Temp1, Key2, Temp2);
	DesEncrypt(Temp2, Key3, Temp1);
	Xor(in, Temp1, 8, out);
	memcpy(ICVCurrent, ICV, 8);
	for (cbCurrent = 8; cbCurrent < cbIn; cbCurrent += 8)
	{
		if (ICVCurrent[7] == 0xff)
		{
			ICVTemp = 0;
			for (i = 0; i < 8; i++)
			{
				ICVTemp <<= 8;
				ICVTemp += ICVCurrent[i];
			}
			ICVTemp++;
			for (i = 0; i < 8; i++)
			{
				ICVCurrent[7 - i] = (BYTE)(ICVTemp & 0xff);
				ICVTemp >>= 8;
			}
		}
		else
		{
			ICVCurrent[7]++;
		}

		DesEncrypt(ICVCurrent, Key1, Temp1);
		DesDecrypt(Temp1, Key2, Temp2);
		DesEncrypt(Temp2, Key3, Temp1);
		Xor(&in[cbCurrent], Temp1, 8, &out[cbCurrent]);
	}

	return;
}

#define DES_MODE_ECB 1
#define DES_MODE_CBC 2
#define DES_MODE_CFB 3
#define DES_MODE_OFB 4
#define DES_MODE_CTR 5

// DES による暗号化と複合化のテスト用関数
VOID WINAPI DesEncryptDecrypt(BYTE* in, DWORD cbIn, BYTE* OriginalKey, BYTE* IV, BYTE* out, DWORD dwMode)
{
	DWORD i;
	BYTE* pInTemp;

	printf("%-22s = ", "Input");
	for (i = 0; i < cbIn; i++)
	{
		printf("%02x", in[i]);
		if (i % 8 == 7)
		{
			printf(" ");
		}
	}
	printf("\r\n");

	printf("%-22s = ", "Key");
	for (i = 0; i < 8; i++)
	{
		printf("%02x", OriginalKey[i]);
	}
	printf("\r\n");

	printf("%-22s = ", "Initialization Vector");
	for (i = 0; i < 8; i++)
	{
		printf("%02x", IV[i]);
	}
	printf("\r\n");

	switch (dwMode)
	{
	case DES_MODE_ECB:
		DesEcbEncryptDecrypt(in, cbIn, OriginalKey, out);

		printf("%-22s = ", "Cipher Text (ECB)");
		for (i = 0; i < cbIn; i++)
		{
			printf("%02x", out[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");

		pInTemp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
		memcpy(pInTemp, out, cbIn);
		DesEcbEncryptDecrypt(pInTemp, cbIn, OriginalKey, out);
		HeapFree(GetProcessHeap(), 0, pInTemp);

		break;

	case DES_MODE_CBC:
		DesCbcEncrypt(in, cbIn, OriginalKey, IV, out);

		printf("%-22s = ", "Cipher Text (CBC)");
		for (i = 0; i < cbIn; i++)
		{
			printf("%02x", out[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");

		pInTemp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
		memcpy(pInTemp, out, cbIn);
		DesCbcDecrypt(pInTemp, cbIn, OriginalKey, IV, out);
		HeapFree(GetProcessHeap(), 0, pInTemp);

		break;

	case DES_MODE_CFB:
		DesCfbEncrypt(in, cbIn, OriginalKey, IV, out);

		printf("%-22s = ", "Cipher Text (CFB)");
		for (i = 0; i < cbIn; i++)
		{
			printf("%02x", out[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");

		pInTemp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
		memcpy(pInTemp, out, cbIn);
		DesCfbDecrypt(pInTemp, cbIn, OriginalKey, IV, out);
		HeapFree(GetProcessHeap(), 0, pInTemp);

		break;

	case DES_MODE_OFB:
		DesOfbEncryptDecrypt(in, cbIn, OriginalKey, IV, out);

		printf("%-22s = ", "Cipher Text (OFB)");
		for (i = 0; i < cbIn; i++)
		{
			printf("%02x", out[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");

		pInTemp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
		memcpy(pInTemp, out, cbIn);
		DesOfbEncryptDecrypt(pInTemp, cbIn, OriginalKey, IV, out);
		HeapFree(GetProcessHeap(), 0, pInTemp);

		break;

	default:
		DesEncrypt(in, OriginalKey, out);

		printf("%-22s = ", "Cipher Text");
		for (i = 0; i < cbIn; i++)
		{
			printf("%02x", out[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");

		pInTemp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
		memcpy(pInTemp, out, cbIn);
		DesDecrypt(pInTemp, OriginalKey, out);
		HeapFree(GetProcessHeap(), 0, pInTemp);

		break;
	}

	printf("%-22s = ", "Output");
	for (i = 0; i < cbIn; i++)
	{
		printf("%02x", out[i]);
		if (i % 8 == 7)
		{
			printf(" ");
		}
	}
	printf("\r\n");

	return;
}

VOID WINAPI TdeaEncryptDecrypt(BYTE* in, DWORD cbIn, BYTE* Key1, BYTE* Key2, BYTE* Key3, BYTE* IVorICV, BYTE* out, DWORD dwMode)
{
	BYTE* pInTemp;
	DWORD i;

	printf("%-22s = ", "Input");
	for (i = 0; i < cbIn; i++)
	{
		printf("%02x", in[i]);
		if (i % 8 == 7)
		{
			printf(" ");
		}
	}
	printf("\r\n");

	printf("%-22s = ", "Key1");
	for (i = 0; i < 8; i++)
	{
		printf("%02x", Key1[i]);
	}
	printf("\r\n");

	printf("%-22s = ", "Key2");
	for (i = 0; i < 8; i++)
	{
		printf("%02x", Key2[i]);
	}
	printf("\r\n");

	printf("%-22s = ", "Key3");
	for (i = 0; i < 8; i++)
	{
		printf("%02x", Key3[i]);
	}
	printf("\r\n");

	printf("%-22s = ", "IV or ICV");
	for (i = 0; i < 8; i++)
	{
		printf("%02x", IVorICV[i]);
	}
	printf("\r\n");

	switch (dwMode)
	{
	case DES_MODE_ECB:
		TdeaEcbEncrypt(in, cbIn, Key1, Key2, Key3, out);

		printf("%-22s = ", "Cipher Text (TDEA-ECB)");
		for (i = 0; i < cbIn; i++)
		{
			printf("%02x", out[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");

		pInTemp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
		memcpy(pInTemp, out, cbIn);

		TdeaEcbDecrypt(pInTemp, cbIn, Key1, Key2, Key3, out);

		break;
	case DES_MODE_CBC:
		TdeaCbcEncrypt(in, cbIn, Key1, Key2, Key3, IVorICV, out);

		printf("%-22s = ", "Cipher Text (TDEA-CBC)");
		for (i = 0; i < cbIn; i++)
		{
			printf("%02x", out[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");

		pInTemp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
		memcpy(pInTemp, out, cbIn);

		TdeaCbcDecrypt(pInTemp, cbIn, Key1, Key2, Key3, IVorICV, out);

		break;
	case DES_MODE_CFB:
		TdeaCfbEncrypt(in, cbIn, Key1, Key2, Key3, IVorICV, out);

		printf("%-22s = ", "Cipher Text (TDEA-CFB)");
		for (i = 0; i < cbIn; i++)
		{
			printf("%02x", out[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");

		pInTemp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
		memcpy(pInTemp, out, cbIn);

		TdeaCfbDecrypt(pInTemp, cbIn, Key1, Key2, Key3, IVorICV, out);

		break;
	case DES_MODE_OFB:
		TdeaOfbEncryptDecrypt(in, cbIn, Key1, Key2, Key3, IVorICV, out);

		printf("%-22s = ", "Cipher Text (TDEA-OFB)");
		for (i = 0; i < cbIn; i++)
		{
			printf("%02x", out[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");

		pInTemp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
		memcpy(pInTemp, out, cbIn);

		TdeaOfbEncryptDecrypt(pInTemp, cbIn, Key1, Key2, Key3, IVorICV, out);

		break;
	case DES_MODE_CTR:
		TdeaCtrEncryptDecrypt(in, cbIn, Key1, Key2, Key3, IVorICV, out);

		printf("%-22s = ", "Cipher Text (TDEA-CTR)");
		for (i = 0; i < cbIn; i++)
		{
			printf("%02x", out[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");

		pInTemp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
		memcpy(pInTemp, out, cbIn);

		TdeaCtrEncryptDecrypt(pInTemp, cbIn, Key1, Key2, Key3, IVorICV, out);

		break;
	default:
		TdeaEncrypt(in, Key1, Key2, Key3, out);

		printf("%-22s = ", "Cipher Text (TDEA)");
		for (i = 0; i < cbIn; i++)
		{
			printf("%02x", out[i]);
			if (i % 8 == 7)
			{
				printf(" ");
			}
		}
		printf("\r\n");

		pInTemp = (BYTE*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbIn);
		memcpy(pInTemp, out, cbIn);
		TdeaDecrypt(pInTemp, Key1, Key2, Key3, out);

		break;
	}

	printf("%-22s = ", "Output");
	for (i = 0; i < cbIn; i++)
	{
		printf("%02x", out[i]);
		if (i % 8 == 7)
		{
			printf(" ");
		}
	}
	printf("\r\n");
}

INT __cdecl main(INT argc, CHAR* argv[])
{
	// DES による暗号化テスト

	// Example 1
	// DES (CBC)
	// Input = "Now is the time for all " (4e6f772069732074 68652074696d6520 666f7220616c6c20)
	// Key = 0123456789abcdef
	// IV = 1234567890abcdef
	// Cipher Text (ECB) = 3fa40e8a984d4815 6a271787ab8883f9 893d51ec4b563b53
	// Cipher Text (CBC) = e5c7cdde872bf27c 43e934008c389c0f 683788499a7c05f6
	// Cipher Text (CFB) = f3096249c7f46e51 a69e839b1a92f784 03467133898ea622
	// Cipher Text (OFB) = f3096249c7f46e51 35f24a242eeb3d3f 3d6d5be3255af8c3
	CHAR DesExample1_Input[] = "Now is the time for all ";
	DWORD DesExample1_CbInput = 24;
	BYTE DesExample1_Key[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
	BYTE DesExample1_IV[8] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
	BYTE DesExample1_Output[24] = { 0 };
	DesEncryptDecrypt((BYTE*)DesExample1_Input, DesExample1_CbInput, DesExample1_Key, DesExample1_IV, DesExample1_Output, DES_MODE_ECB);
	printf("\r\n");
	DesEncryptDecrypt((BYTE*)DesExample1_Input, DesExample1_CbInput, DesExample1_Key, DesExample1_IV, DesExample1_Output, DES_MODE_CBC);
	printf("\r\n");
	DesEncryptDecrypt((BYTE*)DesExample1_Input, DesExample1_CbInput, DesExample1_Key, DesExample1_IV, DesExample1_Output, DES_MODE_CFB);
	printf("\r\n");
	DesEncryptDecrypt((BYTE*)DesExample1_Input, DesExample1_CbInput, DesExample1_Key, DesExample1_IV, DesExample1_Output, DES_MODE_OFB);
	printf("\r\n");

	// TDEA による暗号化テスト

	// Example 1
	// Input = "The qufc" = 5468652071756663
	// Key1 = 0123456789ABCDEF
	// Key2 = 23456789ABCDEF01
	// Key3 = 456789ABCDEF0123
	// Cipher Text = A826FD8CE53B855F
	CHAR TdeaExample1_Input[] = "The qufc";
	DWORD TdeaExample1_CbInput = 8;
	BYTE TdeaExample1_Key1[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
	BYTE TdeaExample1_Key2[8] = { 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01 };
	BYTE TdeaExample1_Key3[8] = { 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23 };
	BYTE TdeaExample1_IV[8] = { 0 };
	BYTE TdeaExample1_Output[8] = { 0 };
	TdeaEncryptDecrypt((BYTE*)TdeaExample1_Input, 8, TdeaExample1_Key1, TdeaExample1_Key2, TdeaExample1_Key3, TdeaExample1_IV, TdeaExample1_Output, 0);
	printf("\r\n");

	// Example 2
	// Input = 6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
	// Key1 = 01234567 89ABCDEF
	// Key2 = 23456789 ABCDEF01
	// Key3 = 01234567 89ABCDEF
	// Cipher Text = 06ede3d8 2884090a ff322c19 f0518486 73057697 2a666e58 b6c88cf1 07340d3d
	BYTE TdeaExample2_Input[] = {
		0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
		0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
		0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
		0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51 };
	DWORD TdeaExample2_CbInput = 32;
	BYTE TdeaExample2_Key1[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
	BYTE TdeaExample2_Key2[8] = { 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01 };
	BYTE TdeaExample2_Key3[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
	BYTE TdeaExample2_IV[8] = { 0 };
	BYTE TdeaExample2_Output[32] = { 0 };
	TdeaEncryptDecrypt(TdeaExample2_Input, TdeaExample2_CbInput, TdeaExample2_Key1, TdeaExample2_Key2, TdeaExample2_Key3, TdeaExample2_IV, TdeaExample2_Output, DES_MODE_ECB);
	printf("\r\n");

	// Example 3
	// Input = 6BC1BEE2 2E409F96 E93D7E11 7393172A AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
	// Key1 = 01234567 89ABCDEF
	// Key2 = 23456789 ABCDEF01
	// Key3 = 456789AB CDEF0123
	// IV = F69F2445 DF4F9B17
	// Cipher Text (ECB) = 714772F3 39841D34 267FCC4B D2949CC3 EE11C22A 576A3038 76183F99 C0B6DE87
	// Cipher Text (CBC) = 2079c3d5 3aa763e1 93b79e25 69ab5262 51657048 1f25b50f 73c0bda8 5c8e0da7
	// Cipher Text (CFB) = 078BB74E 59CE7ED6 7666DE9C F95EAF3F E9ED6BB4 60F45152 8A5F9FE4 ED710918
	// Cipher Text (OFB) = 078BB74E 59CE7ED6 267E1206 92667DA1 A58662D7 E04CBC64 2144D55C 03DB5AEE
	// Cipher Text (CTR) = 078BB74E 59CE7ED6 19AA11D2 5004FB65 A03CEDF1 BA0B09BA A3BC81B8 F69C1DA9
	BYTE TdeaExample3_Input[] = {
		0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96,
		0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A,
		0xAE, 0x2D, 0x8A, 0x57, 0x1E, 0x03, 0xAC, 0x9C,
		0x9E, 0xB7, 0x6F, 0xAC, 0x45, 0xAF, 0x8E, 0x51 };
	DWORD TdeaExample3_CbInput = 32;
	BYTE TdeaExample3_Key1[8] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
	BYTE TdeaExample3_Key2[8] = { 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01 };
	BYTE TdeaExample3_Key3[8] = { 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23 };
	BYTE TdeaExample3_IV[8] = { 0xF6, 0x9F, 0x24, 0x45, 0xDF, 0x4F, 0x9B, 0x17 };
	BYTE TdeaExample3_Output[32] = { 0 };
	TdeaEncryptDecrypt(TdeaExample3_Input, TdeaExample3_CbInput, TdeaExample3_Key1, TdeaExample3_Key2, TdeaExample3_Key3, TdeaExample3_IV, TdeaExample3_Output, DES_MODE_ECB);
	printf("\r\n");
	TdeaEncryptDecrypt(TdeaExample3_Input, TdeaExample3_CbInput, TdeaExample3_Key1, TdeaExample3_Key2, TdeaExample3_Key3, TdeaExample3_IV, TdeaExample3_Output, DES_MODE_CBC);
	printf("\r\n");
	TdeaEncryptDecrypt(TdeaExample3_Input, TdeaExample3_CbInput, TdeaExample3_Key1, TdeaExample3_Key2, TdeaExample3_Key3, TdeaExample3_IV, TdeaExample3_Output, DES_MODE_CFB);
	printf("\r\n");
	TdeaEncryptDecrypt(TdeaExample3_Input, TdeaExample3_CbInput, TdeaExample3_Key1, TdeaExample3_Key2, TdeaExample3_Key3, TdeaExample3_IV, TdeaExample3_Output, DES_MODE_OFB);
	printf("\r\n");
	TdeaEncryptDecrypt(TdeaExample3_Input, TdeaExample3_CbInput, TdeaExample3_Key1, TdeaExample3_Key2, TdeaExample3_Key3, TdeaExample3_IV, TdeaExample3_Output, DES_MODE_CTR);
	printf("\r\n");

	return 0;
}