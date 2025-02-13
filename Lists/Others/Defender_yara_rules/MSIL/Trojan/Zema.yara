rule Trojan_MSIL_Zema_A_2147788495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zema.A!MTB"
        threat_id = "2147788495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zema"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "fdsfds.exe" ascii //weight: 5
        $x_5_2 = "VirtualProtect" ascii //weight: 5
        $x_5_3 = "ToBase64String" ascii //weight: 5
        $x_5_4 = "BlockCopy" ascii //weight: 5
        $x_1_5 = "vfdvdfdvfvdf" wide //weight: 1
        $x_1_6 = "tndfgbf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Zema_SBP_2147794292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zema.SBP!MTB"
        threat_id = "2147794292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zema"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sdfsdfsd" ascii //weight: 1
        $x_1_2 = "fasasdasdas.exe" ascii //weight: 1
        $x_1_3 = "Decrypt" ascii //weight: 1
        $x_1_4 = "m_IsRepG2Decoders" ascii //weight: 1
        $x_1_5 = "SetDictionarySize" ascii //weight: 1
        $x_1_6 = "DecodeWithMatchByte" ascii //weight: 1
        $x_1_7 = "UpdateShortRep" ascii //weight: 1
        $x_1_8 = "get_CurrentDomain" ascii //weight: 1
        $x_1_9 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zema_GD_2147795838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zema.GD!MTB"
        threat_id = "2147795838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zema"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "$PEEP_HUMAN_PERSON_AVATAR_ICON_19" wide //weight: 10
        $x_10_2 = "MASK_FACE_EXPRESSION_ICON_192515" wide //weight: 10
        $x_1_3 = "sdvsdsdvds" ascii //weight: 1
        $x_1_4 = "vsdvsdvdsvsd" ascii //weight: 1
        $x_1_5 = "vsdvsdvsd" ascii //weight: 1
        $x_1_6 = "vsdvsdsv" ascii //weight: 1
        $x_1_7 = "ResolveSignature" ascii //weight: 1
        $x_1_8 = "get_CurrentDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

