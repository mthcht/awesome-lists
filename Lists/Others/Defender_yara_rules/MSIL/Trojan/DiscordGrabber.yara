rule Trojan_MSIL_DiscordGrabber_RDA_2147894292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DiscordGrabber.RDA!MTB"
        threat_id = "2147894292"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DiscordGrabber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 21 00 00 0a 0b 07 28 42 00 00 0a 16 fe 01 0c 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

