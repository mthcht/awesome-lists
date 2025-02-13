rule Trojan_MSIL_RevShell_RDA_2147908436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RevShell.RDA!MTB"
        threat_id = "2147908436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RevShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 73 15 00 00 0a 0c 08 17 6f 16 00 00 0a 00 08 18 6f 17 00 00 0a 00 08 06 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

