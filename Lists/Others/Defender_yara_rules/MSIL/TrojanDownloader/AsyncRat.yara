rule TrojanDownloader_MSIL_AsyncRat_CH_2147851349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRat.CH!MTB"
        threat_id = "2147851349"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 07 11 04 11 07 91 20 ?? ?? ?? ?? 59 d2 9c 00 11 07 17 58 13 07 11 07 11 04 8e 69 fe 04 13 08 11 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRat_CCHZ_2147905552_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRat.CCHZ!MTB"
        threat_id = "2147905552"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 14 11 14 6f ?? 00 00 0a 26 73 ?? ?? ?? ?? 13 15 11 15 72 ?? 06 00 70 73 ?? ?? ?? 0a 06 07 28 ?? 00 00 0a 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 16 11 16 72}  //weight: 1, accuracy: Low
        $x_1_2 = "DisableCMD" wide //weight: 1
        $x_1_3 = "Sideload" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_AsyncRat_CCJR_2147937003_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/AsyncRat.CCJR!MTB"
        threat_id = "2147937003"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 06 07 28 ?? 01 00 0a 16 6f ?? 01 00 0a 13 07 12 07 28 ?? 01 00 0a 6f ?? 01 00 0a 07 11 06 12 01 28 ?? 01 00 0a 2d d8}  //weight: 5, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "Select * from AntivirusProduct" wide //weight: 1
        $x_1_4 = "RunBotKiller" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

