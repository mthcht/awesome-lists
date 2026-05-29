rule TrojanDownloader_MSIL_Cerbu_SX_2147968045_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Cerbu.SX!MTB"
        threat_id = "2147968045"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {06 16 7e 08 00 00 04 14 72 ?? 00 00 70 08 14 14 07 28 ?? 00 00 0a 28 23 00 00 0a 28 23 00 00 0a 28 23 00 00 0a a2 28 2e 00 00 0a 14 72 ?? 00 00 70 06}  //weight: 30, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Cerbu_ARR_2147970482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Cerbu.ARR!MTB"
        threat_id = "2147970482"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 08 16 7e ?? 00 00 04 28 ?? ?? ?? ?? a2 00 08 17 7e ?? 00 00 04 28 ?? ?? ?? ?? a2 00 08 0d 09 14 14 18}  //weight: 10, accuracy: Low
        $x_6_2 = "$9f39354f-4e0b-46b4-817b-e1d0efe04162" ascii //weight: 6
        $x_4_3 = "Class.exe" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

