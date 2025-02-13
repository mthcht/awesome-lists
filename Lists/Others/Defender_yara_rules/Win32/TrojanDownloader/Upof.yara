rule TrojanDownloader_Win32_Upof_A_2147659025_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Upof.A"
        threat_id = "2147659025"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Upof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 00 61 00 6d 00 61 00 6c 00 6f 00 6d 00 [0-32] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 6d 00 61 00 6a 00 61 00 6b 00 69 00 6c 00 2e 00 69 00 6e 00 2f 00 [0-240] 55 00 70 00 64 00 61 00 74 00 65 00 4f 00 66 00 66 00 69 00 63 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "ASLASLKK224.dll" wide //weight: 1
        $x_1_3 = "default.b64" wide //weight: 1
        $x_1_4 = {2e 00 62 00 61 00 74 00 [0-32] 63 00 6f 00 70 00 79 00 20 00 [0-32] 3a 00 74 00 72 00 79 00 [0-32] 64 00 65 00 6c 00 20 00 22 00 [0-64] 69 00 66 00 20 00 65 00 78 00 69 00 73 00 74 00 20 00 22 00 [0-32] 22 00 20 00 67 00 6f 00 74 00 6f 00 20 00 74 00 72 00 79 00 [0-32] 6f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 62 00 61 00 74 00 [0-32] 3a 00 74 00 72 00 79 00 [0-32] 64 00 65 00 6c 00 20 00 22 00 [0-64] 69 00 66 00 20 00 65 00 78 00 69 00 73 00 74 00 20 00 22 00 [0-32] 22 00 20 00 67 00 6f 00 74 00 6f 00 20 00 74 00 72 00 79 00 [0-32] 6f 00 70 00 65 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_6 = {4d 00 41 00 48 00 44 00 49 00 [0-32] 6d 00 61 00 68 00 64 00 69 00 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
        $x_1_7 = "/khaki/Abi/UUUU.htm" wide //weight: 1
        $x_1_8 = {77 77 77 2e 6d 61 6a 61 6b 69 6c 2e 69 6e 2f [0-240] 55 70 64 61 74 65 4f 66 66 69 63 65 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_9 = "ASLASLKK224.dll" ascii //weight: 1
        $x_1_10 = {2e 62 61 74 [0-32] 63 6f 70 79 20 [0-32] 3a 74 72 79 [0-32] 64 65 6c 20 22 [0-64] 69 66 20 65 78 69 73 74 20 22 [0-32] 22 20 67 6f 74 6f 20 74 72 79 [0-32] 6f 70 65 6e}  //weight: 1, accuracy: Low
        $x_10_11 = {0f 84 08 01 00 00 89 06 66 81 7e 04 b3 d7 0f 85 ?? ?? 00 00 66 ff 4e 04 6a 00 ff 36 e8 ?? ?? ?? ff 40 0f 84 ?? ?? 00 00 2d ?? ?? 00 00 73 ?? 31 c0 6a 00 6a 00 50 ff 36 e8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

