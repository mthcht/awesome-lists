rule Trojan_MSIL_Sabsik_FGR_2147781621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sabsik.FGR!MTB"
        threat_id = "2147781621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fa 25 33 00 16 00 00 01 ?? ?? ?? 11 ?? ?? ?? 15 ?? ?? ?? f2 ?? ?? ?? 10 ?? ?? ?? 31 ?? ?? ?? 0a ?? ?? ?? 1c}  //weight: 10, accuracy: Low
        $x_3_2 = "High:{0}, Low:{1}" ascii //weight: 3
        $x_3_3 = "lpCurrentDirectory" ascii //weight: 3
        $x_3_4 = "lpStartupInfo" ascii //weight: 3
        $x_3_5 = "lpProcessInformation" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Sabsik_FTR_2147781622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sabsik.FTR!MTB"
        threat_id = "2147781622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {1f 20 20 00 80 00 00 73 4b 00 00 0a 0b 04 14 14 07 20 00 80 00 00 03 28 25 00 00 06 26 07 17 8d 76 00 00 01 6f 4c 00 00 0a 73 4d 00 00 0a 0c 08 08 6f 4e 00 00 0a 18 da 18 6f 4f 00 00 0a 00 08 0a 2b 00 06 2a}  //weight: 10, accuracy: High
        $x_3_2 = "MessageSurrogateFilter" ascii //weight: 3
        $x_3_3 = "LOGO" ascii //weight: 3
        $x_3_4 = "GetKeys" ascii //weight: 3
        $x_3_5 = "INIFiles" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Sabsik_DB_2147797341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Sabsik.DB!MTB"
        threat_id = "2147797341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Sabsik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DKSKSDSDLKSJDLKSDSDS" ascii //weight: 1
        $x_1_2 = "REtTS1NEU0RMS1NKRExLU0RTRFMl" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

