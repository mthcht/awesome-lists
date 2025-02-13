rule TrojanDownloader_Win32_Zeprotad_A_2147600910_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Zeprotad.A"
        threat_id = "2147600910"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Zeprotad"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 57 56 8d 85 ?? ?? ff ff 68 00 80 00 00 50 e8 ?? ?? 00 00 83 c4 ?? 3b c7 89 45 0c 7d 07 33 c0 e9 ?? 00 00 00 6a 02 57 50 e8 ?? ?? 00 00 83 c4 ?? 3d 88 13 00 00 ff 75 0c 7f}  //weight: 10, accuracy: Low
        $x_5_2 = {99 b9 28 23 00 00 f7 f9 8d 85 a8 fe ff ff 52 50 8d 85 a8 fe ff ff 68 e0 40 41 00}  //weight: 5, accuracy: High
        $x_5_3 = {83 f8 07 0f 87 df 01 00 00 ff 24 85 ?? ?? 40 00 8d 45 d8 68 a0 41 41 00}  //weight: 5, accuracy: Low
        $x_1_4 = "p00.dat?id=" ascii //weight: 1
        $x_1_5 = {24 77 69 6e 64 6f 77 73 5c 73 6f 75 6e 64 6c 69 62 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {24 77 69 6e 64 6f 77 73 5c 73 6f 75 6e 64 67 75 69 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {24 77 69 6e 64 6f 77 73 5c 66 6c 61 73 68 67 61 6d 65 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {24 70 72 6f 67 72 61 6d 6d 69 00}  //weight: 1, accuracy: High
        $x_1_9 = {24 73 79 73 74 65 6d 5c 6e 65 74 73 68 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {2f 25 73 3f 69 64 3d 25 69 26 75 3d 25 73 26 76 3d 30 00}  //weight: 1, accuracy: High
        $x_1_11 = "set allowedprogram program = \"%s\" name = \"securesystd\" mode = ENABLE scope = ALL profile = ALL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

