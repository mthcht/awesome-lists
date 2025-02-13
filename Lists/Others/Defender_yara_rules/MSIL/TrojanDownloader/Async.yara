rule TrojanDownloader_MSIL_Async_GG_2147773253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Async.GG!MTB"
        threat_id = "2147773253"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Async"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-100] 2f 41 73 79 6e 63 43 6c 69 65 6e 74 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Users\\Admin\\Desktop\\AsyncClient.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

