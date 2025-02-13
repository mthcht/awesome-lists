rule TrojanDownloader_MSIL_SmokeLoader_B_2147828366_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/SmokeLoader.B!MTB"
        threat_id = "2147828366"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SmokeLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 25 17 2b 22 00 25 17 2b 24 00 25 14 2b 26 00 2b 2a 20 20 4e 00 00 2b 2a 26 00 1a 2c cf de}  //weight: 1, accuracy: High
        $x_1_2 = {00 73 16 00 00 0a 0c 00 2b 31 16 2b 31 2b 36 2b 3b 00 09 08 6f 17 00 00 0a 00 00 de 11}  //weight: 1, accuracy: High
        $x_1_3 = "powershell" wide //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
        $x_1_5 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

