rule Trojan_Win32_ZeroClear_A_2147839152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZeroClear.A!dha"
        threat_id = "2147839152"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZeroClear"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 d0 63 00 3a 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 d4 5c 00 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 d8 72 00 6f 00}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 dc 67 00 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {c7 45 e0 61 00 6d 00 c7 45 e4 64 00 61 00 c7 45 e8 74 00 61 00 c7 45 ec 5c 00 77 00 c7 45 f0 6c 00 6f 00 c7 45 f4 67 00 2e 00 c7 45 f8 74 00 78 00 c7 45 fc 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

