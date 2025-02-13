rule TrojanDownloader_MSIL_Truado_AC_2147823782_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Truado.AC!MTB"
        threat_id = "2147823782"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Truado"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 05 20 09 ?? ?? 00 28 20 ?? ?? 06 3a 5a ?? ?? 00 38 55 ?? ?? 00 08 28 25 ?? ?? 06 28 26 ?? ?? 06 73 2f ?? ?? 0a 0d 20 06 ?? ?? 00 38 3a ?? ?? 00 00 72 79 ?? ?? 70 72 d8 ?? ?? 70 72 f0 ?? ?? 70 28 21 ?? ?? 06 0a 20 07 ?? ?? 00 38 1a ?? ?? 00 00 07 28 24 ?? ?? 06 0c 38 b8 ?? ?? ff 20 01 ?? ?? 00 fe 0e ?? 00 fe 0c 06 00}  //weight: 4, accuracy: Low
        $x_1_2 = "HttpWebRequest" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

