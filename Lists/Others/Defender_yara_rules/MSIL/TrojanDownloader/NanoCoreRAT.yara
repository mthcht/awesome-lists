rule TrojanDownloader_MSIL_NanoCoreRAT_A_2147837508_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/NanoCoreRAT.A!MTB"
        threat_id = "2147837508"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoCoreRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 2a 19 00 02 28 ?? 00 00 0a 02 28 ?? 00 00 06 73 ?? 00 00 06 7b ?? 00 00 04 02 6f}  //weight: 2, accuracy: Low
        $x_2_2 = {02 2b ce 73 ?? 00 00 0a 2b c9 02 2b d0 28 ?? 00 00 0a 2b cc 02 2b cb 73 ?? 00 00 0a 2b d0 28 ?? 00 00 0a 2b cb 02 2b ca 6f ?? 00 00 0a 2b ca}  //weight: 2, accuracy: Low
        $x_2_3 = {06 8e 69 28 ?? 00 00 0a 02 06 28 ?? 00 00 0a 7d ?? 00 00 04 2a 1a 00 02 28 ?? 00 00 0a 02 28 ?? 00 00 06 02 72 ?? 00 00 70 28 ?? 00 00 06 0a 06 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

