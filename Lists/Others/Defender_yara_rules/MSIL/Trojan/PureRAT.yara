rule Trojan_MSIL_PureRAT_AMTB_2147960765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRAT!AMTB"
        threat_id = "2147960765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EnumPureCrypterInjection" ascii //weight: 1
        $x_1_2 = "EnumPureCrypterFakeApp" ascii //weight: 1
        $x_1_3 = "EnumPureCrypterStartup" ascii //weight: 1
        $x_1_4 = "EnumPureCrypterFakeMessageType" ascii //weight: 1
        $x_1_5 = "PureRAT.exe" ascii //weight: 1
        $x_1_6 = "PureHVNC_Lib.Enums" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRAT_SO_2147974257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRAT.SO!MTB"
        threat_id = "2147974257"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {7e 42 00 00 04 07 9a 06 28 61 00 00 0a 39 0b 00 00 00 7e 43 00 00 04 74 2a 00 00 01 2a 07 17 58 0b 07 7e 42 00 00 04 8e 69 3f d2 ff ff ff}  //weight: 3, accuracy: High
        $x_1_2 = "TripleDES" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureRAT_YYZ_2147975276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureRAT.YYZ!MTB"
        threat_id = "2147975276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fe 0c 08 00 fe 0c 0e 00 fe 0c 0f 00 6f ?? ?? 00 0a fe 0e 10 00 fe 0c 0c 00 fe 0c 0d 00 25 28 ?? ?? 00 06 58 fe 0e 0d 00 fe 0d 10 00 28 ?? ?? 00 0a 9c fe 0c 0d 00 fe 0c 0b 00 fe 04 28 ?? ?? 00 06 fe 01 fe 0e 1d 00 fe 0c 1d 00 3a 1d 00 00 00 fe 0c 0c 00 fe 0c 0d 00 25}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

