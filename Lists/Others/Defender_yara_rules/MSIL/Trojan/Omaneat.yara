rule Trojan_MSIL_Omaneat_KAAE_2147920819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Omaneat.KAAE!MTB"
        threat_id = "2147920819"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Omaneat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 09 1a 5a 59 7e ?? 00 00 04 1f 7a 7e ?? 00 00 04 1f 7a 93 05 61 20 ?? 00 00 00 5f 9d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

