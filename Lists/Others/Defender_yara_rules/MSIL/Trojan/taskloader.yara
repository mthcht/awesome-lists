rule Trojan_MSIL_TaskLoader_AB_2147793605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TaskLoader.AB!MTB"
        threat_id = "2147793605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TaskLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 13 0d 38 4b 05 00 00 11 0d 1c 62 13 0e 16 13 0f 38 3e 00 00 00 06 11 0f 18 64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 e0 91 1f 10 62 60 07 11 0e 11 0f 17 58 58 e0 91 1e 62 60 07 11 0e 11 0f 58 e0 91 60 9e 11 0f 1a 58 13 0f 11 0f 1f 3d}  //weight: 10, accuracy: High
        $x_3_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 3
        $x_3_3 = "sihost" ascii //weight: 3
        $x_3_4 = "Host for System Info" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TaskLoader_AA_2147794049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TaskLoader.AA!MTB"
        threat_id = "2147794049"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TaskLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 bd a2 3d 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 c8 00 00 00 43 00 00 00 9a}  //weight: 10, accuracy: High
        $x_3_2 = "inetinfo" ascii //weight: 3
        $x_3_3 = "WebDownload" ascii //weight: 3
        $x_3_4 = "GetSpecialDirectoryPath" ascii //weight: 3
        $x_3_5 = "GetDelegateForFunctionPointer" ascii //weight: 3
        $x_3_6 = "NetworkInfoHost.Properties.Resources" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

