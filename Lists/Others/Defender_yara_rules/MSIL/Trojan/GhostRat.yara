rule Trojan_MSIL_GhostRat_ARG_2147934596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GhostRat.ARG!MTB"
        threat_id = "2147934596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 06 16 13 07 2b 14 11 06 11 07 11 05 11 07 91 1f 7f 5f d1 9d 11 07 17 58 13 07 11 07 11 04 32 e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_GhostRat_AGR_2147934694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GhostRat.AGR!MTB"
        threat_id = "2147934694"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 09 1e 5b 91 1d 11 09 1e 5d 59 1f 1f 5f 63 17 5f 60 7d ?? ?? ?? 04 11 0c 11 04 17 59 2f 10 11 0a 11 0a 7b ?? ?? ?? 04 17 62 7d ?? ?? ?? 04 11 09 17 58 13 09 11 0c 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_GhostRat_PAGS_2147956752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/GhostRat.PAGS!MTB"
        threat_id = "2147956752"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GhostRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Telegram Stealer" ascii //weight: 2
        $x_2_2 = "StealTData" ascii //weight: 2
        $x_1_3 = "CopyFromScreen" ascii //weight: 1
        $x_1_4 = "Telegram Data" wide //weight: 1
        $x_1_5 = "System Info" wide //weight: 1
        $x_1_6 = "BOT_TOKEN" ascii //weight: 1
        $x_2_7 = "CaptureDesktopScreenshot" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

