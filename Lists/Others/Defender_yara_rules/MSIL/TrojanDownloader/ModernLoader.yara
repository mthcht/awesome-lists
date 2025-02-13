rule TrojanDownloader_MSIL_ModernLoader_AML_2147849917_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/ModernLoader.AML!MTB"
        threat_id = "2147849917"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ModernLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 0f 00 00 06 d0 29 00 00 01 28 ?? ?? ?? 0a 72 f5 00 00 70 28 ?? ?? ?? 0a 16 8c 2b 00 00 01 14 6f ?? ?? ?? 0a 74 1a 00 00 01 0a 25 06 72 09 01 00 70 28}  //weight: 2, accuracy: Low
        $x_1_2 = "Sandbox execution is not allowed" wide //weight: 1
        $x_1_3 = "Virtual machine execution is not allowed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

