rule TrojanDownloader_MSIL_Taskun_CCHZ_2147905797_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Taskun.CCHZ!MTB"
        threat_id = "2147905797"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Taskun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 02 11 03 11 01 11 03 91 72 2f 00 00 70 ?? 0b 00 00 06 59 d2 9c 20 1e 00 00 00 38}  //weight: 1, accuracy: Low
        $x_1_2 = "80.66.75.44" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

