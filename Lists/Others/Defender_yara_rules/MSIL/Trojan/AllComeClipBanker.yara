rule Trojan_MSIL_AllComeClipBanker_A_2147835635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AllComeClipBanker.A!MTB"
        threat_id = "2147835635"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AllComeClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JHFSASN KASFH" wide //weight: 1
        $x_1_2 = "ISDFJ8Y IOAJF" wide //weight: 1
        $x_1_3 = "DFSSFJIW AWWR" wide //weight: 1
        $x_1_4 = "ToInteger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_AllComeClipBanker_B_2147835780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AllComeClipBanker.B!MTB"
        threat_id = "2147835780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AllComeClipBanker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 13 07 03 11 07 91 13 08 16 16 11 08 8c ?? 00 00 01 11 06 8c ?? 00 00 01 18 28 ?? ?? 00 06 13 09 28 ?? ?? 00 06 17 8d ?? 00 00 01 25 16 11 04 8c ?? 00 00 01 a2 14 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0a 06 74 ?? 00 00 1b 11 04 16 16 11 0a 8c ?? 00 00 01 11 09 8c ?? 00 00 01 18 28 ?? ?? 00 06 b4 9c 11 04 17 d6 13 04}  //weight: 2, accuracy: Low
        $x_1_2 = "ToInteger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

