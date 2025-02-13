rule TrojanDownloader_Win32_Frethog_S_2147596432_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Frethog.S"
        threat_id = "2147596432"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallNextHookEx" ascii //weight: 1
        $x_1_2 = "Accept:" ascii //weight: 1
        $x_1_3 = "Agent%ld" ascii //weight: 1
        $x_1_4 = "Accept: */*" ascii //weight: 1
        $x_4_5 = "SetDIPSHook" ascii //weight: 4
        $x_1_6 = "GetSystemDirectoryA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Frethog_C_2147615403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Frethog.C"
        threat_id = "2147615403"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 64 72 69 76 65 72 73 5c 6b 6c 69 66 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_2_2 = {4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 70 72 6f 74 65 63 74 65 64 5c 41 56 50 37 5c 70 72 6f 66 69 6c 65 73 5c 55 70 64 61 74 65 72 00}  //weight: 2, accuracy: High
        $x_3_3 = {41 4e 54 49 56 4d 2e 64 6c 6c 00 4b 41 56 5f 47 6f 75 74 00 53 79 73 44 61 74 61 42 75 66 66 65 72 00}  //weight: 3, accuracy: High
        $x_2_4 = {6a 08 50 68 73 00 09 00 ff 75 fc ff 15 ?? ?? 00 10 85 c0}  //weight: 2, accuracy: Low
        $x_2_5 = {8d 45 d0 53 50 57 ff 75 08 ff 75 f0 ff 15 ?? ?? 00 10 01 7d 08 83 c6 08 ff 4d 0c 75 d3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Frethog_E_2147651200_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Frethog.E"
        threat_id = "2147651200"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Frethog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Can not start victim process!" wide //weight: 1
        $x_1_2 = {5c 00 a2 5b 37 62 ef 7a 5c 00 6e 00 6f 00 74 00 65 00 70 00 61 00 64 00 2e 00 76 00 62 00 70}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e [0-32] 2e 00 6e 00 65 00 74 00 2f 00 66 00 69 00 6c 00 65 00 2e 00 74 00 78 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

