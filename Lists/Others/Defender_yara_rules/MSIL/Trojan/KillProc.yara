rule Trojan_MSIL_KillProc_SK_2147895742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillProc.SK!MTB"
        threat_id = "2147895742"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillProc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {17 8d 1a 00 00 01 13 07 11 07 16 72 23 00 00 70 a2 11 07 73 1f 00 00 0a 0c}  //weight: 2, accuracy: High
        $x_2_2 = {11 0a 11 09 9a 13 05 11 05 6f 23 00 00 0a 09 28 24 00 00 0a 6f 25 00 00 0a 2c 07 11 05 6f 26 00 00 0a 11 09 17 d6 13 09 11 09 11 0a 8e b7 32 d0}  //weight: 2, accuracy: High
        $x_2_3 = "Payload.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KillProc_SWK_2147925454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillProc.SWK!MTB"
        threat_id = "2147925454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillProc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 11 05 9a 0b 28 ?? 00 00 0a 00 07 28 ?? 00 00 0a 13 08 16 13 07 2b 14 11 08 11 07 9a 0c 08 6f ?? 00 00 0a 00 11 07 17 d6 13 07 00 11 07 11 08 8e b7 fe 04 13 09 11 09 2d de 11 05 17 d6 13 05 00 11 05 11 06 8e b7 fe 04 13 09 11 09 2d b0}  //weight: 2, accuracy: Low
        $x_2_2 = {00 73 3c 00 00 0a 0a 06 6f 3d 00 00 0a 00 2b 07 28 ?? 00 00 0a 00 00 06 6f ?? 00 00 0a 02 20 e8 03 00 00 d8 6a fe 04 0b 07 2d e5 06 6f ?? 00 00 0a 00 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_KillProc_MA_2147926202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/KillProc.MA!MTB"
        threat_id = "2147926202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "KillProc"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MemoryDiagnostic.exe" wide //weight: 1
        $x_1_2 = "$483eb30c-11bd-4335-b672-3e7a34a02ba7" ascii //weight: 1
        $x_1_3 = "MinhaLiistaas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

