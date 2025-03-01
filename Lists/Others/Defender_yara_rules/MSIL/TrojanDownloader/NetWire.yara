rule TrojanDownloader_MSIL_NetWire_A_2147824427_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/NetWire.A!MTB"
        threat_id = "2147824427"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NetWire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 11 01 03 11 ?? 91 6f ?? ?? ?? 0a 38 ?? ?? ?? ff 11 ?? 2a 03 8e 69 13 ?? 38 ?? ?? ?? ff 11 ?? 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b 13 03}  //weight: 1, accuracy: Low
        $x_1_2 = {03 73 09 00 ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 73 ?? ?? ?? 0a 20 ?? ?? ?? 03 6f ?? ?? ?? 0a 13 00 38}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

