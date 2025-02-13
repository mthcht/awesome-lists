rule TrojanDownloader_MSIL_Blocker_AAT_2147927331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Blocker.AAT!MTB"
        threat_id = "2147927331"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {30 4c 02 7b ?? 00 00 04 06 02 7b ?? 00 00 04 02 7b ?? 00 00 04 03 28 ?? 00 00 0a 02 02 7b ?? 00 00 04 03 58 7d ?? 00 00 04 2a 02 7b ?? 00 00 04 02 02 7b ?? 00 00 04 0c 08 17 58 7d ?? 00 00 04 08}  //weight: 5, accuracy: Low
        $x_1_2 = "$e80cf74f-63bf-4d6b-8364-c7baaad3a2ec" ascii //weight: 1
        $x_1_3 = "ConsoleApp48.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

