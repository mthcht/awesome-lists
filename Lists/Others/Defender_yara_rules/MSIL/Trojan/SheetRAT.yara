rule Trojan_MSIL_SheetRAT_DGRS_2147972022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SheetRAT.DGRS!MTB"
        threat_id = "2147972022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SheetRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WindowsUpdateDefender.exe" ascii //weight: 1
        $x_1_2 = "Google LLC" ascii //weight: 1
        $x_1_3 = "type=activation&code=" ascii //weight: 1
        $x_1_4 = "Pastebin content is empty" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SheetRAT_LVN_2147982833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SheetRAT.LVN!MTB"
        threat_id = "2147982833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SheetRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 05 00 fe 0c 0e 00 fe ?? 00 00 fe 0c 0e 00 91 fe 0c 10 00 61 28 ?? 01 00 0a 9c 28 ?? 09 00 06 fe 0e 13 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

