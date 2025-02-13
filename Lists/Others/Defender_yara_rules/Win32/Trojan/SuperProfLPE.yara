rule Trojan_Win32_SuperProfLPE_A_2147814644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuperProfLPE.A!ibt"
        threat_id = "2147814644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuperProfLPE"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 72 65 61 74 65 6d 6f 75 6e 74 70 6f 69 6e 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {63 72 65 61 74 65 6e 61 74 69 76 65 73 79 6d 6c 69 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 65 78 65 2e 6c 6f 63 61 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 63 6f 6d 63 74 6c 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = {6e 74 63 72 65 61 74 65 73 79 6d 62 6f 6c 69 63 6c 69 6e 6b 6f 62 6a 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {63 6f 6e 76 65 72 74 73 74 72 69 6e 67 73 65 63 75 72 69 74 79 64 65 73 63 72 69 70 74 6f 72 74 6f 73 65 63 75 72 69 74 79 64 65 73 63 72 69 70 74 6f 72 77 00}  //weight: 1, accuracy: High
        $x_1_7 = {6e 74 75 73 65 72 2e 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

