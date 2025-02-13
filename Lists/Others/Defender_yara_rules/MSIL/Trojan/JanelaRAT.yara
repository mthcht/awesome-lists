rule Trojan_MSIL_JanelaRAT_ZB_2147932430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/JanelaRAT.ZB!MTB"
        threat_id = "2147932430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "JanelaRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Janela>k" ascii //weight: 1
        $x_1_2 = "set_Janela" ascii //weight: 1
        $x_1_3 = "get_SystemInfos" ascii //weight: 1
        $x_1_4 = "hookStruct" ascii //weight: 1
        $x_1_5 = "GetRecycled" ascii //weight: 1
        $x_1_6 = "FromBase64String" ascii //weight: 1
        $x_1_7 = "ToBase64String" ascii //weight: 1
        $x_1_8 = "get_MachineName" ascii //weight: 1
        $x_1_9 = "WriteAllText" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

