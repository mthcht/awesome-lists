rule TrojanDownloader_MSIL_Cobaltstrike_WFB_2147919037_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Cobaltstrike.WFB!MTB"
        threat_id = "2147919037"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cobaltstrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 00 00 fe 0c 01 00 fe 0c 00 00 fe 0c 01 00 93 20 91 58 d8 ea 20 b1 83 d8 ea 59 20 05 00 00 00 63 66 20 02 00 00 00 63 61 fe 09 00 00 61 d1 9d fe 0c 01 00 20 0c ca 20 0a 20 01 00 00 00 62 65 66 20 03 c9 8c 1d 61 66 65 20 ea a2 32 f6 61 65 59 25 fe 0e 01 00 20 ff ff ff ff 66 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

