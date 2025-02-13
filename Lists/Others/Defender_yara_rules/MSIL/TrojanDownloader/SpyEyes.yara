rule TrojanDownloader_MSIL_SpyEyes_AM_2147818859_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/SpyEyes.AM!MTB"
        threat_id = "2147818859"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SpyEyes"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "C:\\ProgramData\\checker.exe" wide //weight: 2
        $x_2_2 = "C:\\ProgramData\\componentn.exe" wide //weight: 2
        $x_2_3 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2f 00 63 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 6e 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_2_4 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2f 00 63 00 68 00 65 00 63 00 6b 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_5 = "DownloadFile" ascii //weight: 1
        $x_1_6 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

