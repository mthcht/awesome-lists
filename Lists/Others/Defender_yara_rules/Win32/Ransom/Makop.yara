rule Ransom_Win32_Makop_PA_2147750960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Makop.PA!MTB"
        threat_id = "2147750960"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Makop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 03 44 24 38 8b cd 89 44 24 10 8b 44 24 1c 03 c5 c1 e9 05 03 4c 24 2c 89 44 24 20 89 3d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 8b 44 24 20 31 44 24 10 81 3d ?? ?? ?? ?? 72 07 00 00 75}  //weight: 1, accuracy: Low
        $x_10_2 = {33 4c 24 10 89 7c 24 14 2b f1 89 74 24 18 81 f3 07 eb dd 13 81 6c 24 14 52 ef 6f 62 b8 41 e5 64 03 81 6c 24 14 68 19 2a 14 81 44 24 14 be 08 9a 76 8b 4c 24 14 8b c6 d3 e0 03 44 24 30 81 3d ?? ?? ?? ?? 1a 0c 00 00 89 44 24 10 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Makop_SS_2147759315_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Makop.SS!MTB"
        threat_id = "2147759315"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Makop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "edzjkphvesw.uxe" wide //weight: 1
        $x_1_2 = "InternalSurnames" wide //weight: 1
        $x_1_3 = "Tog cejumu sivajudakamof diwixo" wide //weight: 1
        $x_1_4 = "DVomekil cofataloxowedos kofomujiloguru dokunuv zihatexope hopalitebo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Makop_AY_2147761507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Makop.AY!MSR"
        threat_id = "2147761507"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Makop"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tog cejumu sivajudakamof diwixo" ascii //weight: 1
        $x_1_2 = "edzjkphvesw.uxe" ascii //weight: 1
        $x_1_3 = "&;B`u]a" ascii //weight: 1
        $x_1_4 = "Vubaduyesalo zeja" ascii //weight: 1
        $x_1_5 = "Xozifa sohupicowadico" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Makop_SA_2147889069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Makop.SA!MTB"
        threat_id = "2147889069"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Makop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 c1 ea ?? 03 54 24 ?? 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 7c 24 ?? 8b 44 24 ?? d1 6c 24 ?? 29 44 24 ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Makop_Z_2147959338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Makop.Z!MTB"
        threat_id = "2147959338"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Makop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 18 83 c4 0c 8b 4f 0c 03 c6 50 8d 54 24 18 52 51 6a 00 6a 00 89 44 24 28 8b 44 24 3c}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 75 15 8b 44 24 10 8b 4c 24 08 8b 54 24 0c 89 46 20 89}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

