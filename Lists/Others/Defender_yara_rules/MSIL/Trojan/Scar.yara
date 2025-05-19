rule Trojan_MSIL_Scar_EHH_2147941736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Scar.EHH!MTB"
        threat_id = "2147941736"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Scar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {14 11 06 11 07 ?? ?? ?? ?? ?? 26 09 17 58 0d 11 07 17 58 13 07 11 07 11 06 ?? ?? ?? ?? ?? 32 e1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

