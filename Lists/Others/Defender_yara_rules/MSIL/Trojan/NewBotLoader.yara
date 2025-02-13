rule Trojan_MSIL_NewBotLoader_CCHT_2147905134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NewBotLoader.CCHT!MTB"
        threat_id = "2147905134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NewBotLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a a2 25 20 02 00 00 00 20 ?? 00 00 00 28 2a 00 00 0a a2 25 20 03 00 00 00 20 ?? 00 00 00 28 2a 00 00 0a a2 25 20 04 00 00 00 20 ?? 00 00 00 28 2a 00 00 0a a2 25 20 05 00 00 00 20 ?? 00 00 00 28 2a 00 00 0a a2 25 20 06 00 00 00 20 ?? 00 00 00 28 2a 00 00 0a a2 25 20 07 00 00 00 20 ?? 00 00 00 28 2a 00 00 0a a2 25 20 08 00 00 00 20 ?? 00 00 00 28 2a 00 00 0a a2 25 20 09 00 00 00 20 ?? 00 00 00 28 2a 00 00 0a a2 25}  //weight: 1, accuracy: Low
        $x_1_2 = "<GetInstalledEdr>" ascii //weight: 1
        $x_1_3 = "<Inject>" ascii //weight: 1
        $x_1_4 = "get_Payload" ascii //weight: 1
        $x_1_5 = "get_DomainControllerSiteName" ascii //weight: 1
        $x_1_6 = "get_DomainControllerForestName" ascii //weight: 1
        $x_1_7 = "get_InstalledAntiMalware" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NewBotLoader_CCHU_2147905631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NewBotLoader.CCHU!MTB"
        threat_id = "2147905631"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NewBotLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 45 00 00 00 28 ?? 00 00 0a a2 25 20 01 00 00 00 20 72 00 00 00 28 ?? 00 00 0a a2 25 20 02 00 00 00 20 72 00 00 00 28 ?? 00 00 0a a2 25 20 03 00 00 00 20 6f 00 00 00 28 ?? 00 00 0a a2 25 20 04 00 00 00 20 72 00 00 00 28 ?? 00 00 0a a2 28 ?? 00 00 0a fe 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

