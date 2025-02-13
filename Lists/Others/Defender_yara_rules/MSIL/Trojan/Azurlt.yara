rule Trojan_MSIL_Azurlt_2147760040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Azurlt!MTB"
        threat_id = "2147760040"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azurlt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vroombrooomkrooom" ascii //weight: 1
        $x_1_2 = "kekedoyouloveme" ascii //weight: 1
        $x_1_3 = "Debugger" ascii //weight: 1
        $x_1_4 = "IsLogging" ascii //weight: 1
        $x_1_5 = "Synchronized" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

