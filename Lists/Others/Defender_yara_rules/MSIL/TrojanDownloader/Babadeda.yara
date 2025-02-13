rule TrojanDownloader_MSIL_Babadeda_RDB_2147842265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Babadeda.RDB!MTB"
        threat_id = "2147842265"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Babadeda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "525d5f31-6887-4068-9459-ef343d9c4793" ascii //weight: 1
        $x_2_2 = {08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

