rule Backdoor_MSIL_SpyGate_DCC_2147752455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/SpyGate.DCC!MTB"
        threat_id = "2147752455"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1b 11 05 a2 00 11 09 1c 11 08 a2 00 11 09 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b 28 ?? ?? ?? ?? 07 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 14 14 6f ?? ?? ?? ?? 74 ?? ?? ?? ?? 13 06 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_SpyGate_AAHU_2147851820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/SpyGate.AAHU!MTB"
        threat_id = "2147851820"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 01 00 00 70 0b 07 72 46 0d 01 70 72 4a 0d 01 70 6f ?? 00 00 0a 0c 08 28 ?? 00 00 0a 13 04 11 04 28 ?? 00 00 0a 0d 09 28 ?? 00 00 0a 0a 06 14}  //weight: 4, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_SpyGate_KA_2147852433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/SpyGate.KA!MTB"
        threat_id = "2147852433"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 00 2a 00 34 00 43 00 2a 00 77 00 2a 00 67}  //weight: 1, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "StrReverse" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_SpyGate_SK_2147936258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/SpyGate.SK!MTB"
        threat_id = "2147936258"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyGate"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {03 6f 27 00 00 0a 25 26 26 08 17 58 0c 08 1a 32 ef}  //weight: 2, accuracy: High
        $x_2_2 = "58e103f0.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

