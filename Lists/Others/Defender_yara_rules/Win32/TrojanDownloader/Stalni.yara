rule TrojanDownloader_Win32_Stalni_2147601169_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stalni"
        threat_id = "2147601169"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stalni"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3e c7 02 63 6d 64 20 3e c7 42 04 2f 63 20 22}  //weight: 1, accuracy: High
        $x_2_2 = {3e c7 00 22 20 49 4e 3e c7 40 04 53 54 41 4c}  //weight: 2, accuracy: High
        $x_1_3 = {81 78 05 90 90 90 90 74}  //weight: 1, accuracy: High
        $x_1_4 = {81 38 83 7c 24 04 74}  //weight: 1, accuracy: High
        $x_1_5 = {68 6f 6e 00 00 68 75 72 6c 6d}  //weight: 1, accuracy: High
        $x_1_6 = "jlhntdl" ascii //weight: 1
        $x_1_7 = {36 8b 6c 24 24 36 8b 45 3c 36 8b 54 05 78}  //weight: 1, accuracy: High
        $x_1_8 = {3e 8b 4a 18 3e 8b 5a 20}  //weight: 1, accuracy: High
        $x_1_9 = {64 8b 15 30 00 00 00 8d 52 03 80 3a 01 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

