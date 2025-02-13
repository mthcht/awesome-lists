rule TrojanDownloader_MSIL_Nekark_ABNY_2147896331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Nekark.ABNY!MTB"
        threat_id = "2147896331"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {70 2b 24 2b 29 2b 2e 2b 33 2b 34 16 2b 34 8e 69 17 2d 32 26 26 26 1d 2c 02 07 0c 16 2d dc de 55 28 ?? ?? ?? 0a 2b d5 28 ?? ?? ?? 06 2b d5 6f ?? ?? ?? 0a 2b d0 28 ?? ?? ?? 0a 2b cb 0b 2b ca 07 2b c9 07 2b c9 28 ?? ?? ?? 0a 2b ca}  //weight: 5, accuracy: Low
        $x_1_2 = "GetTypes" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

