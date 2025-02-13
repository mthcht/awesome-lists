rule Trojan_Win32_Jinupd_A_2147683422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jinupd.A"
        threat_id = "2147683422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jinupd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f8 05 0f 87 42 01 00 00 ff 24 85 68 68 40 00 80 7c 3a 01 38 75 0e 80 7c 3a 02 30 75 07 80 7c 3a 03 30 74 02 b3 01 b9 04 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 00 6e 00 6a 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 00 4a 00 61 00 76 00 61 00 20 00 53 00 45 00 20 00 50 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00 5c 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {26 74 32 3d 00 00 00 00 2f 62 3f 74 31 3d 00 00 2f 65 63 68 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Jinupd_B_2147683440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jinupd.B"
        threat_id = "2147683440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jinupd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "hack\\dev\\pos\\" ascii //weight: 5
        $x_5_2 = {73 6f 70 5c 52 65 6c 65 61 73 65 5c 73 76 63 68 6f 73 74 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_5_3 = "ziedpirate-PC\\Desktop\\sop" ascii //weight: 5
        $x_5_4 = {73 6f 70 5c 52 65 6c 65 61 73 65 5c 69 6e 6a 2e 70 64 62 00}  //weight: 5, accuracy: High
        $x_10_5 = {50 00 69 00 64 00 31 00 00 00}  //weight: 10, accuracy: High
        $x_10_6 = {4a 00 61 00 76 00 61 00 [0-8] 50 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

