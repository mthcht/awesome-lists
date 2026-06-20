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

