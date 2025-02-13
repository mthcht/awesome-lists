rule TrojanDownloader_MSIL_Azorult_A_2147824426_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Azorult.A!MTB"
        threat_id = "2147824426"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Azorult"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ea 58 66 61 fe ?? ?? 00 61 d1 9d fe ?? ?? 00 20 ?? ?? ?? db 65 20 ?? ?? ?? 24 59 59 25 fe ?? ?? 00 20 ?? ?? ?? 20 20 ?? ?? ?? 17 59 65 20 ?? ?? ?? 08 61 66 20}  //weight: 1, accuracy: Low
        $x_1_2 = {08 11 08 08 11 08 91 11 04 11 08 09 5d 91 61 d2 9c 1f 09 13 0f 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

