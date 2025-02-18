rule Trojan_MSIL_SpideyBot_A_2147824424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpideyBot.A!MTB"
        threat_id = "2147824424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpideyBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 25 72 ?? ?? ?? 70 07 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 25 72 0e 01}  //weight: 1, accuracy: Low
        $x_1_2 = {07 08 9a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {0a 74 19 00 ?? 01 13 ?? 06 11 ?? 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 2d de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SpideyBot_ASI_2147933739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SpideyBot.ASI!MTB"
        threat_id = "2147933739"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpideyBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 07 7e 1a 00 00 04 25 2d 17 26 7e 19 00 00 04 fe 06 46 00 00 06 73 67 00 00 0a 25 80 1a 00 00 04 28 ?? 00 00 2b 0c 08 14 fe 03 0d 09 2c 0b 00 08}  //weight: 3, accuracy: Low
        $x_2_2 = {0a 00 06 0b 16 0c 2b 6c 07 08 9a 0d 00 09 6f ?? 00 00 0a 03 28 ?? 00 00 0a 13 04 11 04 2c 50 00 09 6f ?? 00 00 0a 13 08 12 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

