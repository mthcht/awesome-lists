rule TrojanDownloader_MSIL_PheonixKeylogger_A_2147827730_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/PheonixKeylogger.A!MTB"
        threat_id = "2147827730"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PheonixKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 38 85 00 00 00 38 8a 00 00 00 38 8b 00 00 00 38 8c 00 00 00 38 91 00 00 00 00 73 ?? 00 00 0a 0c 00 2b 31 16 2b 31 2b 36 2b 3b 00 09 08 6f ?? 00 00 0a 00 00 de}  //weight: 1, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "CompressionMode" ascii //weight: 1
        $x_1_5 = "GetTypes" ascii //weight: 1
        $x_1_6 = "ToList" ascii //weight: 1
        $x_1_7 = "OpenRead" ascii //weight: 1
        $x_1_8 = "CopyTo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

