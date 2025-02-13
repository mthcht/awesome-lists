rule TrojanDownloader_MSIL_Stealer_ABF_2147824759_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Stealer.ABF!MTB"
        threat_id = "2147824759"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 6f 07 ?? ?? 0a 00 00 de 0b 09 2c 07 09 6f 08 ?? ?? 0a 00 dc 08 6f 09 ?? ?? 0a 13 04 de 16 48 00 72 01 ?? ?? 70 28 04 ?? ?? 06 0a 06 73 03 ?? ?? 0a 0b 00 73 04 ?? ?? 0a 0c 00 07 16 73 05 ?? ?? 0a 73 06 ?? ?? 0a 0d 00}  //weight: 1, accuracy: Low
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "GetDomain" ascii //weight: 1
        $x_1_5 = "CopyTo" ascii //weight: 1
        $x_1_6 = "InvokeMember" ascii //weight: 1
        $x_1_7 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

