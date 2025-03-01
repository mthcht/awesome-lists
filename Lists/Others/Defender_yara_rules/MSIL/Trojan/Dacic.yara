rule Trojan_MSIL_Dacic_SK_2147895743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dacic.SK!MTB"
        threat_id = "2147895743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b 0c 00 00 04 7b 27 00 00 04 07 17 58 0e 04 07 9a 05 6f ?? ?? ?? 06 07 9a 28 ?? ?? ?? 06 6f ?? ?? ?? 06 07 17 58 0b 07 6e 0e 04 8e 69 6a 32 cf}  //weight: 2, accuracy: Low
        $x_2_2 = "\\charmhost\\obj\\Release\\charmhost.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dacic_GMN_2147907889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dacic.GMN!MTB"
        threat_id = "2147907889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {69 11 0d 20 ?? ?? ?? ?? 61 58 8d ?? ?? ?? ?? 13 0c 20 ?? ?? ?? e8 11 0d 5a 39 ?? ?? ?? ?? 11 08 11 0d 20 ?? ?? ?? ?? 64 13 0d 11 0c 11 0d 20 ?? ?? ?? e8 59 13 0d 11 0d 20 ?? ?? ?? 1b 61 6f ?? ?? ?? 0a 11 0c 11 08 8e 11 0d 20 ?? ?? ?? ?? 59 13 0d 69 11 0d 20 ?? ?? ?? 7c 61 13 0d d0 ?? ?? ?? ?? 20 ?? ?? ?? f5 11 0d 61 13 0d 28 ab 00 00 0a 11 0d 20 0d 82 87 fb 61 13 0d a2 20 ?? ?? ?? b6 11 0d 20 1f 00 00 00 5f 62}  //weight: 10, accuracy: Low
        $x_1_2 = "PLoader.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dacic_ND_2147916581_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dacic.ND!MTB"
        threat_id = "2147916581"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 06 93 0b 06 18 58 93 07 61 0b}  //weight: 5, accuracy: High
        $x_3_2 = "67134.90134.56.09" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dacic_ARA_2147920666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dacic.ARA!MTB"
        threat_id = "2147920666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {58 11 09 fe 02 16 fe 01 13 0a 11 0a 2c 0c 00 08 09 6f ?? ?? ?? 0a 00 00 2b 2a 00 11 09 08 6f ?? ?? ?? 0a 59 13 0b 11 0b 16 fe 02 13 0c 11 0c 2c 12 00 08 09 16 11 0b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 00 00 09 6f ?? ?? ?? 0a 00 11 07 17 58 13 07 00 11 07 07 6f ?? ?? ?? 0a fe 04 13 0d 11 0d 3a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dacic_SL_2147923796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dacic.SL!MTB"
        threat_id = "2147923796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$41b75bfe-ea68-421e-82f3-c50c8f47e80a" ascii //weight: 2
        $x_2_2 = "CompanyNetwork.Properties.Resources" ascii //weight: 2
        $x_1_3 = "Showcard Gothic" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dacic_NI_2147926462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dacic.NI!MTB"
        threat_id = "2147926462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "fb078dbd-b988-40b9-b8b0-9272c73f6ee3" ascii //weight: 2
        $x_1_2 = "CPU_Scheduling" ascii //weight: 1
        $x_1_3 = "ProcessesScheduling" ascii //weight: 1
        $x_1_4 = "InvokeMember" ascii //weight: 1
        $x_1_5 = "NetworkCredential" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Dacic_ASMA_2147934911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dacic.ASMA!MTB"
        threat_id = "2147934911"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dacic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Fj90kFj90eFj90rFj90nFj90eFj90lFj903Fj902Fj90" ascii //weight: 2
        $x_1_2 = "gt7ngt7tgt7dgt7lgt7lgt7" ascii //weight: 1
        $x_2_3 = "hF4RhF4ehF4shF4uhF4mhF4ehF4ThF4hhF4rhF4ehF4ahF4dhF4" ascii //weight: 2
        $x_1_4 = "Nv24WNv24oNv24wNv246Nv244Nv24SNv24eNv24tNv24TNv24hNv24rNv24eNv24aNv24dNv24CNv24oNv24nNv24tNv24eNv24xNv24tNv24" ascii //weight: 1
        $x_1_5 = "tRb3StRb3etRb3ttRb3TtRb3htRb3rtRb3etRb3atRb3dtRb3CtRb3otRb3ntRb3ttRb3etRb3xtRb3ttRb3" ascii //weight: 1
        $x_4_6 = "Fqwbl6VFqwbl6iFqwbl6rFqwbl6tFqwbl6uFqwbl6aFqwbl6lFqwbl6AFqwbl6lFqwbl6lFqwbl6oFqwbl6cFqwbl6EFqwbl6xFqwbl6" ascii //weight: 4
        $x_4_7 = "Gcq1LsRGcq1LseGcq1LsaGcq1LsdGcq1LsPGcq1LsrGcq1LsoGcq1LscGcq1LseGcq1LssGcq1LssGcq1LsMGcq1LseGcq1LsmGcq1LsoGcq1LsrGcq1LsyGcq1Ls" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

