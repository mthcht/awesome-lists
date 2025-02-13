rule TrojanDownloader_MSIL_Mallox_IP_2147894376_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Mallox.IP!MTB"
        threat_id = "2147894376"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 01 00 00 70 28 03 00 00 06 28 09 00 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

