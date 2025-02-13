rule Trojan_MSIL_AntarcticaLoader_DA_2147926525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/AntarcticaLoader.DA!MTB"
        threat_id = "2147926525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AntarcticaLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "LoaderV2.AntiDebugging" ascii //weight: 10
        $x_10_2 = "AntiDump" ascii //weight: 10
        $x_1_3 = "GetPhysicalAddress" ascii //weight: 1
        $x_1_4 = "user_data" ascii //weight: 1
        $x_1_5 = "get_SystemDirectory" ascii //weight: 1
        $x_1_6 = "get_OSVersion" ascii //weight: 1
        $x_1_7 = "get_Platform" ascii //weight: 1
        $x_1_8 = "GetHostName" ascii //weight: 1
        $x_1_9 = "Base64String" ascii //weight: 1
        $x_1_10 = "Reverse" ascii //weight: 1
        $x_1_11 = "expires" ascii //weight: 1
        $x_1_12 = "username" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

