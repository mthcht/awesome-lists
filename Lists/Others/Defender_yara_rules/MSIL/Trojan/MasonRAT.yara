rule Trojan_MSIL_MasonRAT_BV_2147981689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MasonRAT.BV!MTB"
        threat_id = "2147981689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MasonRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MasonRAT" ascii //weight: 1
        $x_1_2 = "AcceptTcpClient" ascii //weight: 1
        $x_1_3 = "get_Connected" ascii //weight: 1
        $x_1_4 = "get_chat" ascii //weight: 1
        $x_1_5 = "get_Micropohne" ascii //weight: 1
        $x_1_6 = "get_spoofer" ascii //weight: 1
        $x_1_7 = "set_Script" ascii //weight: 1
        $x_1_8 = "get_NO_IP" ascii //weight: 1
        $x_1_9 = "get_Coder" ascii //weight: 1
        $x_1_10 = "set_Builder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

