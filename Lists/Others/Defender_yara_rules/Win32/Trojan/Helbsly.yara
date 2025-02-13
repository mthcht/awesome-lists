rule Trojan_Win32_Helbsly_A_2147603163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Helbsly.A"
        threat_id = "2147603163"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Helbsly"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {74 1a 8d 84 24 0c 06 00 00 53 48 8a 1c 08 80 f3 27 88 1c 08 49 75 f4}  //weight: 10, accuracy: High
        $x_5_2 = {df e0 f6 c4 01 74 3d 8d 4c 24 0c 6a 00 51 8b fe 83 c9 ff 33 c0 f2 ae 8b 5d 08 8b 54 24 1c}  //weight: 5, accuracy: High
        $x_5_3 = {3b c3 74 2f 8d 8c 24 94 00 00 00 51 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 8a 84 24 a0 00 00 00 83 c4 0c 3c 2d 75 07}  //weight: 5, accuracy: Low
        $x_5_4 = {85 f6 7e 17 8a 54 24 10 8b 4c 24 08 53 8a 1c 08 32 da 88 1c 08 40 3b c6 7c f3}  //weight: 5, accuracy: High
        $x_5_5 = {8d bc 24 14 04 00 00 c1 e9 02 f3 a5 8b ca 68 92 00 00 00 83 e1 03 8d 84 24 18 04 00 00 53 50 f3 a4 e8}  //weight: 5, accuracy: High
        $x_1_6 = {76 64 70 6c 75 67 69 6e 2e 64 6c 6c 00 76 64 70 6c 75 67 69 6e 5f 73 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
        $x_1_7 = "baiyuanfan@SteelKernelGroup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

