rule TrojanDownloader_Win32_Thoper_A_2147644907_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Thoper.A"
        threat_id = "2147644907"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Thoper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winsvcfs" ascii //weight: 1
        $x_1_2 = {6a 5b 99 5f f7 ff 46 88 45 ff 3b 71 04 7c e5 5f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Thoper_B_2147648519_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Thoper.B"
        threat_id = "2147648519"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Thoper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 46 04 07 30 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 46 04 3d 09 30 00}  //weight: 1, accuracy: High
        $x_1_3 = {6b c0 64 03 c1 0f b7 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Thoper_C_2147651726_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Thoper.C"
        threat_id = "2147651726"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Thoper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 10 03 c6 8a 08 2a 4d 0c 32 4d 0c 02 4d 0c 88 08}  //weight: 1, accuracy: High
        $x_1_2 = "HT: send(%d)" ascii //weight: 1
        $x_1_3 = "POST http://%s/%d HTTP/1.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Thoper_D_2147680343_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Thoper.D"
        threat_id = "2147680343"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Thoper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 25 f2 00 00 66 89 4d fc 50}  //weight: 1, accuracy: High
        $x_1_2 = {81 e9 6a 3b 00 00 66 89 4d fc}  //weight: 1, accuracy: High
        $x_1_3 = {57 b8 25 f2 00 00 68 ?? ?? ?? ?? 56 66 89 44 24 1c}  //weight: 1, accuracy: Low
        $x_1_4 = {81 c1 36 79 00 00 66 89 4d fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

