rule Trojan_MSIL_Malgent_MBAL_2147838669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Malgent.MBAL!MTB"
        threat_id = "2147838669"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Malgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 16 11 04 8c ?? 00 00 01 a2 25 17 07 20 ef 04 00 00 6f ?? 00 00 0a 17 8d ?? 00 00 01 25 16 11 04 8c ?? 00 00 01 07 20 ef 04 00 00 6f}  //weight: 1, accuracy: Low
        $x_1_2 = "i.ibb.co/q1B4wyW/nature-field-gra-130247647" ascii //weight: 1
        $x_1_3 = {05 53 00 74 00 00 03 61 00 00 05 72 00 74}  //weight: 1, accuracy: High
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Malgent_MBAO_2147838730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Malgent.MBAO!MTB"
        threat_id = "2147838730"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Malgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 d4 27 00 00 9d 19 0c 2b a8 06 74 0b 00 00 1b 1c 20 58 35 00 00 9d 06 75 0b 00 00 1b 16 20 d8 33 00 00 9d 1a 0c 2b 8a 06 74 0b 00 00 1b 1d 20 f2 38 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {58 6e 36 34 43 71 6b 39 47 48 62 33 38 4d 63 41 72 31 77 32 00 00 05 01 00 01 00 00 29 01 00 24 34 62 37}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Malgent_PR_2147933223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Malgent.PR!AMTB"
        threat_id = "2147933223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Malgent"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E:\\PROJETOS2023\\CSHARP\\RAT\\MXNOBUGMAG\\Bin\\Release\\msedge_elf.pdb" ascii //weight: 1
        $x_1_2 = "ToString" ascii //weight: 1
        $x_1_3 = "WriteAllBytes" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "KASjDQA7FcOTljmC0PVBUJnBNB7cburrVCK3df0fsdk=" ascii //weight: 1
        $x_1_6 = "sC6zp6p0ui2QzFHKcfq6vYl6CZ3U2Vo7yW1LgKFTJ6Q=" ascii //weight: 1
        $x_1_7 = "l6PjPku2W0NahCbd36HRrMt3OvjY3svw1l1VAr63795ZSuvoliYrT76jhbTr4DE8" ascii //weight: 1
        $x_1_8 = "o2ydLwGi6hIsHroFCdSiRcRHYtZnvb0vCwvSX" ascii //weight: 1
        $x_1_9 = "gZZm0XrYdyIRihnH0golgTnw==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Malgent_PR_2147933223_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Malgent.PR!AMTB"
        threat_id = "2147933223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Malgent"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ToString" ascii //weight: 1
        $x_1_2 = "WriteAllBytes" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "E:\\PROJETOS2023\\CSHARP\\RAT\\MXNOBUGMAG\\Bin\\Release\\VCRUNTIME140.pdb" ascii //weight: 1
        $x_1_5 = "o2ydLwGi6hIsHroFCdSiRcRHYtZnvb0vCwvSX" ascii //weight: 1
        $x_1_6 = "gZZm0XrYdyIRihnH0golgTnw==" ascii //weight: 1
        $x_1_7 = "KASjDQA7FcOTljmC0PVBUJnBNB7cburrVCK3df0fsdk=" ascii //weight: 1
        $x_1_8 = "sC6zp6p0ui2QzFHKcfq6vYl6CZ3U2Vo7yW1LgKFTJ6Q=" ascii //weight: 1
        $x_1_9 = "l6PjPku2W0NahCbd36HRrMt3OvjY3svw1l1VAr63795ZSuvoliYrT76jhbTr4DE8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Malgent_PGM_2147940785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Malgent.PGM!MTB"
        threat_id = "2147940785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Malgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 7b 00 30 00 7d 00 2f 00 7b 00 31 00 7d 00 00 1f 5c 00 73 00 28 00 3f 00 3c 00 6b 00 65 00 79 00 3e 00 2e 00 2a 00 3f 00 29 00 5c 00 2e 00 00 07 6b 00 65 00 79}  //weight: 1, accuracy: High
        $x_1_2 = "info-sec.jp/attach" ascii //weight: 1
        $x_1_3 = "stgsec-info.jp/acon" ascii //weight: 1
        $x_2_4 = "PdfAttachProduction.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

