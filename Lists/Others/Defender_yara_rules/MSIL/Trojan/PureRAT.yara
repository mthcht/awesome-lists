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

