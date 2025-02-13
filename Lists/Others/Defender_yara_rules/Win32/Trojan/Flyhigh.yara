rule Trojan_Win32_Flyhigh_A_2147828003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flyhigh.A"
        threat_id = "2147828003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flyhigh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 61 00 74 00 68 00 20 00 65 00 78 00 63 00 65 00 6c 00 3a 00 20 00 [0-32] 5c 00 78 00 6c 00 73 00 [0-8] 2e 00 78 00 6c 00 73 00 78 00}  //weight: 1, accuracy: Low
        $x_1_2 = {78 6c 41 75 74 6f 4f 70 65 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 66 ad 03 c2 ab 49 75 f6}  //weight: 1, accuracy: High
        $x_2_4 = {8d 40 ff 83 e9 01 75 f8 20 00 b8 02 10 00 00 b9 c4 0f 00 00}  //weight: 2, accuracy: Low
        $x_2_5 = {68 30 bd 00 00 68 ?? ?? ?? ?? 56 e8 ?? ?? ?? 00 83 c4 0c ff d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

