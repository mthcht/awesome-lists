rule Trojan_MSIL_DuplexSpyRat_AFK_2147950630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DuplexSpyRat.AFK!MTB"
        threat_id = "2147950630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DuplexSpyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 03 1b 6f ?? 01 00 0a 0c 08 39 08 00 00 00 00 07 0a 38 13 00 00 00 00 07 17 58 0b 07 28 ?? 00 00 0a 8e 69 fe 04 0d 09 2d c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

