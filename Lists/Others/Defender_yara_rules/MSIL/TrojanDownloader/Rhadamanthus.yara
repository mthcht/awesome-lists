rule TrojanDownloader_MSIL_Rhadamanthus_CA_2147840681_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Rhadamanthus.CA!MTB"
        threat_id = "2147840681"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 04 18 5b 07 11 04 18 6f 15 00 00 0a 1f 10 28 16 00 00 0a 9c 11 04 18 58 13 04 11 04 08 32}  //weight: 5, accuracy: High
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 63 00 6c 00 65 00 61 00 6e 00 69 00 6e 00 67 00 2e 00 68 00 6f 00 6d 00 65 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 70 00 63 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 61 00 63 00 6b 00 61 00 67 00 65 00 73 00 2f 00 [0-31] 2e 00 70 00 6e 00 67 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 74 74 70 3a 2f 2f 63 6c 65 61 6e 69 6e 67 2e 68 6f 6d 65 73 65 63 75 72 69 74 79 70 63 2e 63 6f 6d 2f 70 61 63 6b 61 67 65 73 2f [0-31] 2e 70 6e 67}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

