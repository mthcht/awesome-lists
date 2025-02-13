rule Trojan_MSIL_CinoshiStealer_A_2147843841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CinoshiStealer.A!MTB"
        threat_id = "2147843841"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CinoshiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Cinoshi.pdb" ascii //weight: 2
        $x_2_2 = "Ionic.Zip" ascii //weight: 2
        $x_2_3 = "CreditCardsNotFound" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CinoshiStealer_B_2147843844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CinoshiStealer.B!MTB"
        threat_id = "2147843844"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CinoshiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 ff a2 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 9c 00 00 00 b2 00 00 00 a2 03 00 00 46 07}  //weight: 2, accuracy: High
        $x_2_2 = "Ionic.Zip" ascii //weight: 2
        $x_2_3 = "CreditCardsNotFound" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_CinoshiStealer_C_2147847407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CinoshiStealer.C!MTB"
        threat_id = "2147847407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CinoshiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 fd a2 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 ce 00 00 00 4e 00 00 00 16 02 00 00 db}  //weight: 2, accuracy: High
        $x_1_2 = "RegDeleteKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

