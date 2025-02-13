rule Trojan_Win32_Feplec_A_2147628029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Feplec.A"
        threat_id = "2147628029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Feplec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b1 ff 2a 08 88 08 40 4a 75 f6 c3}  //weight: 1, accuracy: High
        $x_1_2 = {be 00 00 00 10 81 c6 00 00 01 00 6a 40 68 00 30 00 00 8b 47 50 50 8b 47 34 03 c6 50}  //weight: 1, accuracy: High
        $x_2_3 = {8b 00 ff d0 8b f0 60 3b 1d ?? ?? ?? ?? 0f 85 94 00 00 00 83 fe 32 0f 8e 8b 00 00 00 8d 45 f8 8b d7 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

