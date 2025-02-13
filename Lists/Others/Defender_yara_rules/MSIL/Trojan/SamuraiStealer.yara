rule Trojan_MSIL_SamuraiStealer_DA_2147907508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SamuraiStealer.DA!MTB"
        threat_id = "2147907508"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SamuraiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "Samurai.Stealer" ascii //weight: 20
        $x_1_2 = "get_EncryptedUsername" ascii //weight: 1
        $x_1_3 = "get_ComputerName" ascii //weight: 1
        $x_1_4 = "get_CardNumber" ascii //weight: 1
        $x_1_5 = "get_Passwords" ascii //weight: 1
        $x_1_6 = "get_Cookies" ascii //weight: 1
        $x_1_7 = "get_Autofills" ascii //weight: 1
        $x_1_8 = "get_Logins" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SamuraiStealer_SK_2147919613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SamuraiStealer.SK!MTB"
        threat_id = "2147919613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SamuraiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 73 d3 01 00 0a 20 05 00 00 00 20 14 00 00 00 6f d5 01 00 0a fe 0e 01 00 fe 0c 01 00 6c 28 34 00 00 0a fe 0e 02 00}  //weight: 2, accuracy: High
        $x_1_2 = "get_CardNumber" ascii //weight: 1
        $x_1_3 = "get_Cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

