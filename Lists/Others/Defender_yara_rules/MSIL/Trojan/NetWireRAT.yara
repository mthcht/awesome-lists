rule Trojan_MSIL_NetWireRAT_A_2147904651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NetWireRAT.A!MTB"
        threat_id = "2147904651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWireRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 57 03 1e 09 07 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 6d 00 00 00 89 00 00 00 dc 00 00 00 d9 01}  //weight: 2, accuracy: High
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "AppDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

