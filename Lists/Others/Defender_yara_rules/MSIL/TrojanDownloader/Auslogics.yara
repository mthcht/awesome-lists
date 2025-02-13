rule TrojanDownloader_MSIL_Auslogics_SK_2147923163_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Auslogics.SK!MTB"
        threat_id = "2147923163"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Auslogics"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 12 00 00 06 10 00 02 0a dd 03 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

