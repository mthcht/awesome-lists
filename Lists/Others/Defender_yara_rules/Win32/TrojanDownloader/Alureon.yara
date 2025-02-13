rule TrojanDownloader_Win32_Alureon_C_2147803842_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Alureon.C"
        threat_id = "2147803842"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".exe;http://" ascii //weight: 1
        $x_1_2 = "allowedprogram %s enable" ascii //weight: 1
        $x_1_3 = {68 80 96 98 00 6a 40 ff 15 ?? ?? ?? 00 8d 4d ?? 51 68 40 54 89 00 50 53}  //weight: 1, accuracy: Low
        $x_2_4 = {0f 31 83 e0 0a 89 45 ?? 8b 45 ?? 69 c0 e8 03 00 00 50 ff 15}  //weight: 2, accuracy: Low
        $x_2_5 = {80 3b 3b 74 0c ff 45 fc 8b 45 fc 80 3c 18 3b 75 f4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Alureon_E_2147804128_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Alureon.E"
        threat_id = "2147804128"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {45 78 65 63 50 72 69 2e 64 6c 6c 00 68 69 67 68 00 45 78 65 63 57 61 69 74 00}  //weight: 10, accuracy: High
        $x_10_2 = {69 6e 65 74 63 2e 64 6c 6c 00 2f 65 6e 64 00}  //weight: 10, accuracy: High
        $x_1_3 = {2f 63 72 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 69 73 61 73 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {2f 73 64 64 33 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 73 64 6d 36 34 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 66 70 73 73 32 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {5c 73 79 73 6b 65 79 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {5c 77 70 6e 70 69 6e 73 74 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {5c 70 72 65 73 65 6e 74 61 74 69 6f 6e 73 65 74 74 69 6e 67 73 61 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_11 = {5c 65 66 73 75 69 62 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_12 = {5c 62 69 74 73 61 64 6d 69 6e 62 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Alureon_G_2147804167_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Alureon.G"
        threat_id = "2147804167"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Alureon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "34"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\inetc.dll" ascii //weight: 10
        $x_10_2 = "\\ExecPri.dll" ascii //weight: 10
        $x_10_3 = "ExecWait" ascii //weight: 10
        $x_4_4 = {68 74 74 70 3a 2f 2f 69 6e 6c 69 6e 65 34 37 37 2e 69 6e 66 6f 2f 66 73 72 76 [0-32] 2e 65 78 65}  //weight: 4, accuracy: Low
        $x_1_5 = "\\wowreg32a.exe" ascii //weight: 1
        $x_1_6 = "\\fingerb.exe" ascii //weight: 1
        $x_1_7 = "\\fixmapib.exe" ascii //weight: 1
        $x_1_8 = "\\atiesrxxb.exe" ascii //weight: 1
        $x_1_9 = "\\PATHPINGb.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

