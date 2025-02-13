rule TrojanDownloader_MSIL_Injector_A_2147820442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Injector.A!MTB"
        threat_id = "2147820442"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 03 07 91 2b ?? 00 2b ?? 07 25 17 59 0b 16 fe ?? 0c 2b ?? 00 2b ?? 08 2d ?? 2b ?? 2b}  //weight: 1, accuracy: Low
        $x_1_2 = "GetMethod" ascii //weight: 1
        $x_1_3 = "GetType" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

