rule Trojan_Win32_Deepec_A_2147641923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Deepec.A"
        threat_id = "2147641923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Deepec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 65 70 43 6d 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {47 45 54 20 2f 72 64 61 74 61 2f 3f 64 3d 63 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {5c 73 63 2e 76 62 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {4c 61 73 74 44 75 6d 70 48 61 73 68 00}  //weight: 1, accuracy: High
        $x_1_5 = {41 6d 6e 65 73 69 61 63 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 4f 53 54 20 2f 73 32 2f 3f 64 3d 63 69 64 3d 00}  //weight: 1, accuracy: High
        $x_1_7 = {6a 06 6a 01 6a 02 ff 15 ?? ?? ?? 10 89 45 c8 6a 01 e8 ?? ?? ?? 00 59 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

