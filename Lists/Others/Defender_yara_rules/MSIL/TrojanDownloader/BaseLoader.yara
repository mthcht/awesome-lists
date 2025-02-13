rule TrojanDownloader_MSIL_BaseLoader_GNF_2147896970_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/BaseLoader.GNF!MTB"
        threat_id = "2147896970"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BaseLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b7 17 d6 8d ?? ?? ?? ?? 13 06 08 11 06 16 08 6f ?? ?? ?? 0a b7 6f ?? ?? ?? 0a 26 28 ?? ?? ?? 0a 11 06 16 1a 6f ?? ?? ?? 0a 0d 11 06 1a 28 ?? ?? ?? 0a 13 04 11 06 1e 28 ?? ?? ?? 0a 13 05 11 04 16 fe 01 11 05 16 fe 01 60 13 0a 11 0a}  //weight: 10, accuracy: Low
        $x_1_2 = "ui\\strdef11.bin" ascii //weight: 1
        $x_1_3 = "AikaDDS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

