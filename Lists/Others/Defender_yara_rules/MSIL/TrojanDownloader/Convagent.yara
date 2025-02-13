rule TrojanDownloader_MSIL_Convagent_EALJ_2147932165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Convagent.EALJ!MTB"
        threat_id = "2147932165"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Convagent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 06 08 72 35 00 00 70 07 72 35 00 00 70 28 32 00 00 0a 6f 33 00 00 0a 28 34 00 00 0a 9d 00 08 17 58 0c 08 03 fe 04 0d 09 2d d5}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

