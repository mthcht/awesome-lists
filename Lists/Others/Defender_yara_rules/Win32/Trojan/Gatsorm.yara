rule Trojan_Win32_Gatsorm_A_2147646911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gatsorm.A"
        threat_id = "2147646911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gatsorm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 46 14 8a 44 86 3c 32 01 88 47 ff 8b 45 ?? 2b 46 14 8a 44 86 3d 32 41 01}  //weight: 1, accuracy: Low
        $x_1_2 = {b2 3f f6 ea 02 45 0c 8b 55 08 c1 fa 04 c0 e0 02 0a c2 8b 55 10}  //weight: 1, accuracy: High
        $x_1_3 = {73 78 63 6e 66 67 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {74 61 67 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {43 49 4e 46 4f 3d 25 73 ?? 55 49 44 3d 25 73 ?? 43 6f 6f 6b 69 65 3a 46 3d 25 73}  //weight: 1, accuracy: Low
        $x_1_6 = {43 49 4e 46 4f 3d 25 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 55 49 44 3d 25 73 ?? 43 6f 6f 6b 69 65 3a 46 3d 25 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

