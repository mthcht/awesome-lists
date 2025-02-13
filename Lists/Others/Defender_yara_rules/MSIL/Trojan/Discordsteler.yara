rule Trojan_MSIL_Discordsteler_ASGB_2147897016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discordsteler.ASGB!MTB"
        threat_id = "2147897016"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discordsteler"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 26 08 20 88 13 00 00 6f ?? 00 00 0a 2c 0a 08 6f ?? 00 00 0a 2d 08 2b 06 08 6f}  //weight: 1, accuracy: Low
        $x_1_2 = {08 09 07 09 91 06 09 06 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 07 8e 69 32 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

