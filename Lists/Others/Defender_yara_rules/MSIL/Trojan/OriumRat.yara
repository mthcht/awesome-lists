rule Trojan_MSIL_OriumRat_CAT_2147967806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/OriumRat.CAT!MTB"
        threat_id = "2147967806"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "OriumRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "oriumratt_" wide //weight: 2
        $x_2_2 = "SCREENSHOT" wide //weight: 2
        $x_2_3 = "cleanup.bat" wide //weight: 2
        $x_2_4 = "DisableTaskMgr" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

