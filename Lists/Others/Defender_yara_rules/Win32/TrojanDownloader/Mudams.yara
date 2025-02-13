rule TrojanDownloader_Win32_Mudams_A_2147691753_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mudams.A"
        threat_id = "2147691753"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mudams"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Administrator\\Desktop\\UR" wide //weight: 1
        $x_1_2 = "d15w6a015w01d56qwd1q5wd" ascii //weight: 1
        $x_1_3 = {54 69 6d 65 72 32 00 00 44 6f 77 6e 6c 6f 61 64 46 69 6c 65}  //weight: 1, accuracy: High
        $x_1_4 = {2f 00 69 00 6e 00 73 00 74 00 61 00 49 00 6c 00 2e 00 65 00 78 00 65 00 [0-8] 77 00 69 00 6e 00 64 00 69 00 72 00 [0-8] 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 [0-8] 69 00 6e 00 73 00 74 00 61 00 49 00 6c 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {35 00 32 00 31 00 2e 00 65 00 78 00 65 00 [0-8] 77 00 69 00 6e 00 64 00 69 00 72 00 [0-8] 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 5c 00 [0-8] 35 00 32 00 31 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanDownloader_Win32_Mudams_B_2147693899_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mudams.B"
        threat_id = "2147693899"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mudams"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "WinHttp.WinHttpRequest.5.1" wide //weight: 2
        $x_2_2 = {47 00 45 00 54 00 [0-16] 4f 00 70 00 65 00 6e 00 [0-16] 73 00 65 00 6e 00 64 00}  //weight: 2, accuracy: Low
        $x_2_3 = {00 55 52 4c 00 44 6f 77 6e 6c 6f 61 64 50 61 74 68 [0-16] 46 69 6c 65 4e 61 6d 65}  //weight: 2, accuracy: Low
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 32 00 31 00 31 00 2e 00 32 00 33 00 33 00 2e 00 31 00 39 00 39 00 2e 00 32 00 32 00 38 00 3a 00 38 00 30 00 38 00 30 00 2f 00 [0-5] 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 31 00 34 00 2e 00 31 00 31 00 30 00 2e 00 31 00 34 00 33 00 2e 00 39 00 32 00 3a 00 38 00 30 00 39 00 30 00 2f 00 [0-5] 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 31 00 34 00 2e 00 31 00 31 00 30 00 2e 00 31 00 34 00 33 00 2e 00 39 00 32 00 3a 00 38 00 30 00 39 00 39 00 2f 00 [0-5] 2f 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

