rule Ransom_MSIL_BlackBit_ABB_2147847025_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlackBit.ABB!MTB"
        threat_id = "2147847025"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 05 00 00 0a 72 01 00 00 70 72 ec 02 00 70 1f 40 28 ?? ?? ?? 06 26 1f 23 28 ?? ?? ?? 0a 72 fe 02 00 70 28 ?? ?? ?? 0a 0a 06 28 ?? ?? ?? 0a 2c 1b 72 1a 03 00 70 72 2e 03 00 70 06 72 2e 03 00 70}  //weight: 2, accuracy: Low
        $x_1_2 = "This file and all other files in your computer are encrypted by BlackBit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_BlackBit_MA_2147852278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlackBit.MA!MTB"
        threat_id = "2147852278"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 05 00 00 0a 72 01 00 00 70 72 ?? 02 00 70 1f 40 28 01 00 00 06 26 1f 23 28 06 00 00 0a 72 ?? ?? 00 70 28 07 00 00 0a 0a 06 28 08 00 00 0a 2c 1b 72 ?? 03 00 70 72 ?? 03 00 70 06 72 ?? 03 00 70 28 09 00 00 0a 28 0a 00 00 0a 26 2a}  //weight: 5, accuracy: Low
        $x_2_2 = "info.BlackBit" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_BlackBit_AYA_2147937393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlackBit.AYA!MTB"
        threat_id = "2147937393"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "info.BlackBit" wide //weight: 2
        $x_2_2 = "This file and all other files in your computer are encrypted by BlackBit" wide //weight: 2
        $x_1_3 = "If you want to restore this file and rest of your files, Please send us message to this e-mail" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_BlackBit_NIT_2147937967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/BlackBit.NIT!MTB"
        threat_id = "2147937967"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BlackBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 05 00 00 0a 72 01 00 00 70 72 d0 02 00 70 1f 40 28 ?? 00 00 06 26 1f 23 28 ?? 00 00 0a 72 e2 02 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 0a 2c 1b 72 fe 02 00 70 72 12 03 00 70 06 72 12 03 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "info.BlackBit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

