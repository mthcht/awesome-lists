rule TrojanDownloader_Win32_Korklic_A_2147617422_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Korklic.A"
        threat_id = "2147617422"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Korklic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 40 00 70 10 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 25 73 5c 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 2e 25 63 25 63 25 63 00}  //weight: 1, accuracy: High
        $x_1_2 = "WinToServerProgram" ascii //weight: 1
        $x_1_3 = {25 73 3f 6d 6f 64 65 3d 62 6f 6f 74 26 4d 79 56 61 6c 75 65 3d 25 73 26 63 6f 64 65 3d 25 73 00 68 74 74 70 3a 2f 2f 77 77 77 2e}  //weight: 1, accuracy: High
        $x_1_4 = {00 72 00 00 00 5c 4b 43 50 6f 69 6e 74 5f 49 6e 66 6f 4e 65 77 2e 64 61 74 00 00 00 00 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Korklic_B_2147617423_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Korklic.B"
        threat_id = "2147617423"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Korklic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {67 64 70 6f 69 6e 74 2e 63 6f 2e 6b 72 2f 70 64 73 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {67 6f 6f 64 6d 70 6f 69 6e 74 2e 63 6f 2e 6b 72 2f 70 64 73 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = {62 69 67 6d 6d 6d 2e 63 6f 2e 6b 72 2f 70 64 73 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {66 66 70 6f 74 73 2e 6e 65 74 2f 70 64 73 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {70 6f 69 6e 74 6c 69 6e 65 2e 6f 72 2e 6b 72 2f 70 64 73 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = {73 68 6f 70 6c 69 6e 65 2e 6f 72 2e 6b 72 2f 70 64 73 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_7 = {62 69 67 70 6f 69 6e 74 2e 6f 72 2e 6b 72 2f 70 64 73 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_8 = {64 70 6f 69 6e 74 73 68 6f 70 2e 63 6f 6d 2f 70 64 73 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_9 = {70 74 70 6f 69 6e 74 2e 6e 65 74 2f 70 64 73 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_10 = {62 65 67 69 6e 70 6f 69 6e 74 2e 6e 65 74 2f 70 64 73 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_11 = {70 74 6c 69 6e 65 2e 6e 65 74 2f 70 64 73 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_12 = "kcpoint.com/mylist.htm?MyValue=%s" ascii //weight: 1
        $x_15_13 = "c_ValueFromClick=20100561%%7C%%3A%%7C0000411074%%7C%%3A%%7C00%%7C%%3A%%7C%s%%7C%%3A%%7C%s%%7C%%3A%%7COK; domain=%s" ascii //weight: 15
        $x_15_14 = "%s\\KCPoint_Info.dat" ascii //weight: 15
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 1 of ($x_1_*))) or
            ((2 of ($x_15_*))) or
            (all of ($x*))
        )
}

