rule Trojan_Win32_Waqlop_A_2147692471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Waqlop.A"
        threat_id = "2147692471"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Waqlop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 54 1f ff f6 d2 88 54 18 ff 43 4e 75}  //weight: 1, accuracy: High
        $x_1_2 = {a3 b2 96 9c 8d 90 8c 90 99 8b a3 00}  //weight: 1, accuracy: High
        $x_1_3 = {9e 8f 8f 9b 9e 8b 9e 00}  //weight: 1, accuracy: High
        $x_1_4 = {57 51 4c 00 ?? ?? ?? ?? ?? ?? ?? ?? 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d}  //weight: 1, accuracy: Low
        $x_1_5 = "\\Users\\Public\\Winsetup32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

