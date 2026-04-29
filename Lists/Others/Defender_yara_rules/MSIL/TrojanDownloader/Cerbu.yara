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

