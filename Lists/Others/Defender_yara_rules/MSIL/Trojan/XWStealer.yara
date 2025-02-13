rule Trojan_MSIL_XWStealer_DA_2147851175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/XWStealer.DA!MTB"
        threat_id = "2147851175"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XWStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XWorm" ascii //weight: 1
        $x_1_2 = "OfflineKeylogger" ascii //weight: 1
        $x_1_3 = "api.telegram.org/bot" ascii //weight: 1
        $x_1_4 = "Select * from AntivirusProduct" ascii //weight: 1
        $x_1_5 = "-ExecutionPolicy Bypass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

