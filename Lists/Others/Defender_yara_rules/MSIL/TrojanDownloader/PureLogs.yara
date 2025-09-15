rule TrojanDownloader_MSIL_PureLogs_PTM_2147952229_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PureLogs.PTM!MTB"
        threat_id = "2147952229"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogs"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {73 02 00 00 0a 0b 07 72 ad 00 00 70 6f 03 00 00 0a 0a dd 0d 00 00 00 07 39 06 00 00 00 07}  //weight: 4, accuracy: High
        $x_3_2 = {00 0a 13 04 08 09 11 04 6f ?? 00 00 0a 13 05 03 73 09 00 00 0a 13 06 11 06 11 05 16 73 0a 00 00 0a 13 07 73 0b 00 00 0a 13 08 11 07 11 08 6f ?? 00 00 0a 11 08 6f ?? 00 00 0a 0a 1f 64 0b dd 0f 00 00 00 11 08 39 07 00 00 00 11 08 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

