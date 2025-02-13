rule Trojan_MSIL_TelegramRat_AUU_2147853366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TelegramRat.AUU!MTB"
        threat_id = "2147853366"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TelegramRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 09 11 09 8e 2c 0f 11 09 28 ?? ?? ?? 2b 6f ?? ?? ?? 0a 17 58 0c 07 6f ?? ?? ?? 0a 11 09 28 ?? ?? ?? 06 26 7e 27 00 00 04 28 ?? ?? ?? 0a}  //weight: 2, accuracy: Low
        $x_1_2 = "Get all commands list sorted by alphabet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TelegramRat_AET_2147853373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TelegramRat.AET!MTB"
        threat_id = "2147853373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TelegramRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 1e 16 13 1f 2b 75 00 7e 25 00 00 04 11 1f 73 a7 00 00 0a 12 11 fe 15 10 00 00 1b 11 11 12 11 fe 15 10 00 00 1b 11 11 14 12 12 fe 15 3d 00 00 01 11 12}  //weight: 2, accuracy: High
        $x_1_2 = "Get all commands list sorted by alphabet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

