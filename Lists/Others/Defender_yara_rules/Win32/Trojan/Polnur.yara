rule Trojan_Win32_Polnur_A_2147650727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Polnur.A"
        threat_id = "2147650727"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Polnur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "IntelMatrixStorageManager" ascii //weight: 1
        $x_1_2 = "iaantmon" ascii //weight: 1
        $x_2_3 = {66 89 0f 48 5f 8d 64 24 00 8a 48 01 40 84 c9 75 f8}  //weight: 2, accuracy: High
        $x_5_4 = {83 c4 18 4f 8a 47 01 47 84 c0 75 f8 b9 0c 00 00 00 be ?? ?? ?? 00 f3 a5 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 66 a5 68 00 00 00 80}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

