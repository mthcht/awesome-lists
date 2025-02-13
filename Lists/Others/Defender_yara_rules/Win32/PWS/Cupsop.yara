rule PWS_Win32_Cupsop_A_2147610968_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cupsop.A"
        threat_id = "2147610968"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cupsop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3c 6d 75 0a 80 7b 05 02 0f 84 ?? ?? 00 00 3c c9 75 0a 80 7b 05 00 0f 84 ?? ?? 00 00 3c 64 0f 85 ?? ?? 00 00 80 7b 05 00 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {75 5e 80 7e 05 02 75 58 8a 56 0c 8d 46 0c 84 d2 74 4e 33 c9 80 fa 2f 74 07 41 80 3c 08 2f 75 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Cupsop_B_2147611047_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Cupsop.B"
        threat_id = "2147611047"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Cupsop"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 09 80 34 31 ?? 41 3b c8 7c f7}  //weight: 1, accuracy: Low
        $x_1_2 = {40 3b 45 fc 7d 11 8a 0c 18 80 f9 2a 74 f2 88 8f ?? ?? ?? ?? 47 eb e9 c6 87 ?? ?? ?? ?? 20}  //weight: 1, accuracy: Low
        $x_1_3 = {c0 e0 02 80 e2 3f 46 0a c2 34 eb 88 04 1e 46 ff 4d f8 75 84}  //weight: 1, accuracy: High
        $x_4_4 = {3c 42 52 3e d4 aa b1 a6 3c 66 6f 6e 74 20 63 6f 6c 6f 72 3d 52 45 44 3e 00}  //weight: 4, accuracy: High
        $x_4_5 = {3c 42 52 3e c8 cb ce ef 32 c3 fb b3 c6 3a 20 00}  //weight: 4, accuracy: High
        $x_4_6 = {c8 cb ce ef 31 b5 c8 bc b6 3a 20 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

