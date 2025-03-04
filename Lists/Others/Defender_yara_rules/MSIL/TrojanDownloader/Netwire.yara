rule TrojanDownloader_MSIL_Netwire_ANW_2147896121_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Netwire.ANW!MTB"
        threat_id = "2147896121"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 43 00 00 70 6f ?? ?? ?? 0a 11 02 28 ?? ?? ?? 0a 72 43 00 00 70 6f ?? ?? ?? 0a 8e 69 5d 91 7e 03 00 00 04 11 02 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

