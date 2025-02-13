rule Trojan_MSIL_PolyRansom_DE_2147810618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PolyRansom.DE!MTB"
        threat_id = "2147810618"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PolyRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Qtbxgzla" ascii //weight: 3
        $x_3_2 = "DowZnlZoadDZata" ascii //weight: 3
        $x_3_3 = "/C timeout 20" ascii //weight: 3
        $x_3_4 = "new/Qtbxgzla.jpg" ascii //weight: 3
        $x_3_5 = "Snssddhohqckofqycvyykup" ascii //weight: 3
        $x_3_6 = "SecurityProtocolType" ascii //weight: 3
        $x_3_7 = "AppDomain" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

