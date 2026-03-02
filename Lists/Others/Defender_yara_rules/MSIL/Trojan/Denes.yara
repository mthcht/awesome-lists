rule Trojan_MSIL_Denes_ADE_2147963989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Denes.ADE!MTB"
        threat_id = "2147963989"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Denes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 0d 00 11 08 17 58 13 08 11 08 11 09 8e 11 06 8c ?? 00 00 01 80 ?? 00 00 04 69 fe 04 0b 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

