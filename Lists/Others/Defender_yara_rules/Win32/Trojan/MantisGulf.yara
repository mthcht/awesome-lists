rule Trojan_Win32_MantisGulf_A_2147945679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MantisGulf.A!dha"
        threat_id = "2147945679"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MantisGulf"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 00 65 00 63 00 6f 00 72 00 64 00 2e 00 6c 00 6f 00 67 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5b 2b 5d 20 53 63 61 6e 6e 69 6e 67 2e 2e 2e 2e 0d 0a 00}  //weight: 1, accuracy: High
        $x_1_3 = {5b 2b 5d 20 53 63 61 6e 6e 69 6e 67 20 63 6f 6d 70 6c 65 74 65 64 20 2c 20 61 6c 6c 20 66 69 6c 65 73 3a 20 00}  //weight: 1, accuracy: High
        $x_1_4 = {5b 21 5d 20 31 20 66 69 6c 65 20 66 61 69 6c 65 64 20 74 6f 20 62 65 20 74 72 61 6e 73 66 65 72 72 65 64 20 62 65 63 61 75 73 65 20 74 68 65 20 66 69 6c 65 20 73 69 7a 65 20 77 61 73 20 30 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 6f 6d 70 72 65 73 73 20 75 6e 73 75 63 65 73 73 21 00}  //weight: 1, accuracy: High
        $x_1_6 = {5b 21 21 5d 20 41 6e 20 65 72 72 6f 72 20 6f 63 63 75 72 72 65 64 20 77 68 69 6c 65 20 65 73 74 61 62 6c 69 73 68 69 6e 67 20 74 68 65 20 63 6f 6e 6e 65 63 74 69 6f 6e 3a 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_MantisGulf_B_2147945680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MantisGulf.B!dha"
        threat_id = "2147945680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MantisGulf"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {54 68 65 20 72 65 71 75 69 72 65 64 20 70 61 72 61 6d 65 74 65 72 73 20 61 72 65 20 6e 6f 74 20 73 70 65 63 69 66 69 65 64 21 0d 0a 00}  //weight: 5, accuracy: High
        $x_1_2 = {2d 00 74 00 69 00 6d 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2d 00 70 00 72 00 6f 00 78 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {2d 00 62 00 6c 00 6f 00 63 00 6b 00 5f 00 73 00 69 00 7a 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {2d 00 6d 00 61 00 78 00 5f 00 73 00 69 00 7a 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {2d 00 6c 00 69 00 6d 00 69 00 74 00 5f 00 75 00 70 00 5f 00 73 00 69 00 7a 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {2d 00 73 00 75 00 66 00 66 00 69 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {2d 00 62 00 6c 00 6f 00 63 00 6b 00 5f 00 73 00 75 00 66 00 66 00 69 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {2d 00 6c 00 69 00 6d 00 69 00 74 00 5f 00 73 00 70 00 65 00 65 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_10 = {2d 00 75 00 6e 00 63 00 5f 00 61 00 75 00 74 00 68 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

