rule TrojanDropper_Win32_Otlard_A_2147624261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Otlard.A"
        threat_id = "2147624261"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {bb 85 00 00 00 88 84 0d ?? ?? ?? ?? 8b c6 99 f7 fb 41 8a c2 b2 03 f6 ea}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 01 6a 01 bb ff 01 0f 00 53}  //weight: 1, accuracy: High
        $x_1_3 = "%c%c%c%04x" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Otlard_B_2147631472_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Otlard.B"
        threat_id = "2147631472"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 85 00 00 00 88 84 35 ?? ?? ?? ?? 8b c3 99 f7 f9 b1 03 46 8a c2 f6 e9}  //weight: 2, accuracy: Low
        $x_1_2 = {6a 01 6a 01 68 ff 01 0f 00 56}  //weight: 1, accuracy: High
        $x_1_3 = {40 f7 45 fc 00 80 00 00 74 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Otlard_D_2147647623_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Otlard.D"
        threat_id = "2147647623"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Otlard"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 45 ff bb ?? ?? ?? ?? 88 84 0d ?? ?? ff ff 8b c6 99 f7 fb 41 8a c2 b2 03 f6 ea 00 45 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 c2 03 32 10 40 80 38 00}  //weight: 1, accuracy: High
        $x_1_3 = {0f 31 69 d0 05 84 08 08 42 0b c1 b8 ff ff 00 00 f7 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

