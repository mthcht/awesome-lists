rule TrojanDownloader_Win32_Thamcower_A_2147638636_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Thamcower.A"
        threat_id = "2147638636"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Thamcower"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "baixando4link" wide //weight: 1
        $x_1_2 = {76 00 6d 00 6d 00 72 00 65 00 67 00 31 00 36 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {52 6f 74 61 43 6f 6d 61 6e 64 6f 00}  //weight: 1, accuracy: High
        $x_1_4 = {4d 61 78 69 6d 75 73 32 30 31 30 00}  //weight: 1, accuracy: High
        $x_1_5 = {70 69 6f 6e 65 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Thamcower_B_2147638809_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Thamcower.B"
        threat_id = "2147638809"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Thamcower"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "baixando4link" wide //weight: 1
        $x_1_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 6f 70 61 64 61 61 66 72 69 63 61 00}  //weight: 1, accuracy: High
        $x_1_4 = {63 68 75 70 61 61 6e 6d 61 72 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Thamcower_C_2147638810_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Thamcower.C"
        threat_id = "2147638810"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Thamcower"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "baixando4link" wide //weight: 1
        $x_1_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 68 75 70 61 61 6e 6d 61 72 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

