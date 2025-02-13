rule Trojan_Win32_Emurbo_A_2147602887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emurbo.A"
        threat_id = "2147602887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emurbo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {76 27 88 04 24 b3 01 8b c6 e8 ?? ?? ?? ff 8b fb 81 e7 ff 00 00 00 8b 16 8a 54 3a ff 80 f2 10 88 54 38 ff 43 fe 0c 24 75 de}  //weight: 3, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 66 6c 79 63 6f 64 65 63 73 2e 63 6f 6d 2f 6f 70 61 2f 75 70 64 61 74 65 2e 70 68 70 3f 61 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {55 70 64 50 6f 69 6e 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {3f 6b 65 79 3d 00 00 00 ff ff ff ff 06 00 00 00 3f 66 69 6e 64 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

