rule Trojan_Win32_Kpot_PA_2147753219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kpot.PA!MTB"
        threat_id = "2147753219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kpot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 02 88 45 ff b0 ?? 8a 5d ff 32 c3 8b 7d f8 03 7d f4 88 07 ff 45 f4 42 81 7d f4 ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {31 db 8b 04 8a 88 c7 88 e3 c1 e8 10 c1 e3 08 88 c3 89 1c 8a 49 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Kpot_RS_2147754627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kpot.RS!MTB"
        threat_id = "2147754627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kpot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 7b 89 04 24 b8 f9 cd 03 00 01 04 24 83 2c 24 7b 8b 04 24 8a 04 10 88 04 11}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e9 05 03 d7 33 c2 03 ce 81 3d ?? ?? ?? ?? 72 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 e9 05 03 d3 33 c2 03 ce 81 3d ?? ?? ?? ?? 72 07 00 00 c7 05 ?? ?? ?? ?? b4 1a 3a df}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Kpot_RA_2147756685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kpot.RA!MTB"
        threat_id = "2147756685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kpot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f3 07 eb dd 13 81 6c 24 ?? 52 ef 6f 62 2d ?? ?? ?? ?? 81 6c 24 ?? 68 19 2a 14 81 44 24 ?? be 08 9a 76}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

