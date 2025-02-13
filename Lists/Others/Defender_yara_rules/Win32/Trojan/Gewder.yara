rule Trojan_Win32_Gewder_A_2147575180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gewder.A"
        threat_id = "2147575180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gewder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2e 65 78 69 74 00 2f 72 6f 62 6f 74 73 2e 74 78 74}  //weight: 2, accuracy: High
        $x_2_2 = "\\0x00last_download_id" ascii //weight: 2
        $x_2_3 = {5f 69 64 00 61 75 74 6f 75 70 64 61 74 65 5f}  //weight: 2, accuracy: High
        $x_2_4 = {5f 69 64 00 64 65 73 69 67 6e 74 65 6d 70 5f}  //weight: 2, accuracy: High
        $x_2_5 = {5f 00 53 6f 66 74 77 61 72 65 5c 4f 44 42 43}  //weight: 2, accuracy: High
        $x_2_6 = "SkF9x3x." ascii //weight: 2
        $x_2_7 = {2e 63 6f 6d 00 2e 65 78 65 00 5c}  //weight: 2, accuracy: High
        $x_1_8 = {2e 74 78 74 00 68 74 74 70 3a 2f 2f 00}  //weight: 1, accuracy: High
        $x_1_9 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_10 = "OpenMutexA" ascii //weight: 1
        $x_1_11 = "GetTickCount" ascii //weight: 1
        $x_1_12 = "RegDeleteValueA" ascii //weight: 1
        $x_1_13 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 5 of ($x_1_*))) or
            ((6 of ($x_2_*) and 3 of ($x_1_*))) or
            ((7 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

