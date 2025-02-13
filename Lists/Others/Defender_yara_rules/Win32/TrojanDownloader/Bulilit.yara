rule TrojanDownloader_Win32_Bulilit_A_2147634635_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bulilit.A"
        threat_id = "2147634635"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulilit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 75 6e 6d 65 41 74 53 74 61 72 74 75 70 [0-8] 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e [0-10] 69 72 73 78 78 64 66 64 74 4e 61 6d 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 65 6c 6c 6f 68 74 74 70 3a 2f 2f [0-32] 3a [0-4] 2f [0-2] 2f 63 6f 75 6e 74 2e 61 73 70}  //weight: 1, accuracy: Low
        $x_1_3 = {25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 25 30 32 58 30 30 30 30 30 30 30 30 30 30 30 30 [0-16] 2e 64 6c 6c [0-8] 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Bulilit_D_2147647260_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bulilit.D"
        threat_id = "2147647260"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulilit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {68 01 00 01 00 68 31 0d 01 06 68 32 0d 01 52}  //weight: 4, accuracy: High
        $x_4_2 = {8d 55 e8 68 00 00 00 20 8d 45 e4 52 8d 4d c4 50 8d 55 08 51 8d 45 e0 52 8b 55 ec 8d 4d d8 50 51 52 e8}  //weight: 4, accuracy: High
        $x_2_3 = "w.dywt.com.cn" ascii //weight: 2
        $x_2_4 = "c:\\123.exe" ascii //weight: 2
        $x_2_5 = "haohack.com/" ascii //weight: 2
        $x_1_6 = "Transfer-Encoding: base64" ascii //weight: 1
        $x_1_7 = "type: multipart/mixed;" ascii //weight: 1
        $x_1_8 = "Mozilla/4.0 (compatible;" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Bulilit_E_2147651582_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Bulilit.E"
        threat_id = "2147651582"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Bulilit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 18 00 00 00 33 c0 8d bc 24 ?? 01 00 00 88 9c 24 ?? 01 00 00 f3 ab 66 ab 68 80 00 00 00 aa e8 ?? ?? ff ff 8a d0 b9 18 00 00 00 8a f2 8d bc 24 ?? 01 00 00 8b c2 68 ff 00 00 00 c1 e0 10 66 8b c2 f3 ab 66 ab aa e8 ?? ?? ff ff 8b c8 83 c4 08 c1 e1 06 2b c8 8d 04 88 c1 e0 03 74}  //weight: 1, accuracy: Low
        $x_1_2 = "SOUN%cM%cN.EXE" ascii //weight: 1
        $x_1_3 = "%s?mac=%s&ver=%s&ProcessNum=%d" ascii //weight: 1
        $x_1_4 = "ChongTxt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

