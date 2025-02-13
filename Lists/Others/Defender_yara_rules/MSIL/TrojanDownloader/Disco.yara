rule TrojanDownloader_MSIL_Disco_PDM_2147929191_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Disco.PDM!MTB"
        threat_id = "2147929191"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Disco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {72 1d 02 00 70 80 07 00 00 04 72 8d 02 00 70 80 08 00 00 04 2a}  //weight: 3, accuracy: High
        $x_2_2 = {00 06 07 06 07 91 7e 04 00 00 04 07 7e 04 00 00 04 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

