rule Trojan_MSIL_Ghostrat_AGT_2147952324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ghostrat.AGT!MTB"
        threat_id = "2147952324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ghostrat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 16 13 05 2b 2f 28 ?? 00 00 06 13 06 72 ?? 01 00 70 12 05 28 ?? 00 00 0a 72 ?? 02 00 70 12 06 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 11 05 17 58 13 05 11 05 1f 0f}  //weight: 1, accuracy: Low
        $x_4_2 = "ss.tanye.online" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

