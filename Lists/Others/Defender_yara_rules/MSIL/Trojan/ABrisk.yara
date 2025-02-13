rule Trojan_MSIL_ABrisk_PSUK_2147852638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ABrisk.PSUK!MTB"
        threat_id = "2147852638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ABrisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 02 16 02 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 07 6f ?? 00 00 0a 13 04 de 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

