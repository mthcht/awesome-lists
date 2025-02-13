rule Trojan_MSIL_Scrop_GPA_2147920475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scrop.GPA!MTB"
        threat_id = "2147920475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 04 74 4f 00 00 01 11 05 11 0a 74 0c 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 75 0c 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scrop_CCJC_2147923090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scrop.CCJC!MTB"
        threat_id = "2147923090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 28 18 00 00 0a 0a 73 19 00 00 0a 28 1a 00 00 0a 72 01 00 00 70 6f 1b 00 00 0a 28 1c 00 00 0a 0b 73 1d 00 00 0a 0c 08 07 6f 1e 00 00 0a 00 08 18 6f 1f 00 00 0a 00 08 18 6f 20 00 00 0a 00 08 6f 21 00 00 0a 0d 09 06 16 06 8e 69 6f 22 00 00 0a 13 04 08 6f 23 00 00 0a 00 28 1a 00 00 0a 11 04 6f 24 00 00 0a 13 05 2b 00 11 05 2a}  //weight: 2, accuracy: High
        $x_1_2 = "<AddToStartupByRegistryAsync>" ascii //weight: 1
        $x_1_3 = "<AddToStartupByStartupFolderAsync>" ascii //weight: 1
        $x_1_4 = "<SendDataLoop>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Scrop_GTZ_2147926057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scrop.GTZ!MTB"
        threat_id = "2147926057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scrop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 17 1a 6f ?? ?? ?? 0a 0b 07 1f 3c 5a 1f 3c 5a 20 e8 03 00 00 5a 0c 08 28 ?? ?? ?? 0a 00 00 17 0d 2b d6}  //weight: 10, accuracy: Low
        $x_10_2 = {06 17 1a 6f ?? ?? ?? 0a 0c 08 1f 3c 5a 1f 3c 5a 20 e8 03 00 00 5a 0d 09 28 ?? ?? ?? 0a 00 00 00 17 13 04 2b c7}  //weight: 10, accuracy: Low
        $x_10_3 = {06 17 1a 6f ?? ?? ?? 0a 0b 07 1f 3c 5a 1f 3c 5a 20 e8 03 00 00 5a 0c 20 60 ea 00 00 28 ?? ?? ?? 0a 00 00 17 0d 2b d2}  //weight: 10, accuracy: Low
        $x_1_4 = "userinfo.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

