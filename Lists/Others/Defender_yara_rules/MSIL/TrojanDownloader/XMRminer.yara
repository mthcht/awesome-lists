rule TrojanDownloader_MSIL_XMRminer_AMNC_2147837451_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/XMRminer.AMNC!MTB"
        threat_id = "2147837451"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "XMRminer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 02 07 1e 6f ?? ?? ?? 0a 25 26 18 28 ?? ?? ?? 0a 25 26 6f ?? ?? ?? 0a 00 00 07 1e 58 0b 07 02 6f ?? ?? ?? 0a 25 26 fe 04 0c 08 2d d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

