rule PWS_Win32_Insephor_A_2147605490_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Insephor.A"
        threat_id = "2147605490"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Insephor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 eb 03 00 00 ba 0b 00 00 00 8b c3 e8 ?? ?? ?? ?? 84 c0 74 12 6a 00 68 eb 03 00 00 68 11 01 00 00 53 e8 ?? ?? ?? ?? b9 e9 03 00 00 ba 06 00 00 00 8b c3 e8 ?? ?? ?? ?? 84 c0 74 12 6a 00 68 e9 03 00 00 68 11 01 00 00 53 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 f8 01 75 1c 68 79 04 00 00 56 e8 ?? ?? ?? ?? 8b f0 6a 00 6a 00 68 f5 00 00 00 56 e8}  //weight: 1, accuracy: Low
        $x_5_3 = {6a 02 6a 00 6a 00 53 e8 ?? ?? ?? ?? 89 04 24 6a 00 6a 00 8b 44 24 08 2d (e0|f4) 00 00 00 50 53 e8 ?? ?? ?? ?? 6a 00 8d 44 24 04 50 68 (e0|f4) 00 00 00 56 53 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Insephor_B_2147609935_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Insephor.B"
        threat_id = "2147609935"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Insephor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 2a bb 01 00 00 00 8d 45 f4 8d 53 05 33 c9 8a 4c 1f ff 83 e9 ?? 33 d1 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {83 3a 01 0f 85 ?? ?? ?? ?? 83 c0 20 66 8b 18 66 c7 42 04 6b 00 66 c7 42 06 4e 00 66 83 fb 6b 0f 84}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

