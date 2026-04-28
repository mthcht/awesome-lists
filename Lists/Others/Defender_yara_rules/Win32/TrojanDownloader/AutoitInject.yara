rule TrojanDownloader_Win32_AutoitInject_GVA_2147967866_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AutoitInject.GVA!MTB"
        threat_id = "2147967866"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AutoitInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 00 2f 00 2f 00 31 00 38 00 35 00 2e 00 31 00 33 00 30 00 2e 00 32 00 34 00 39 00 2e 00 36 00 32 00 2f 00 [0-32] 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3a 2f 2f 31 38 35 2e 31 33 30 2e 32 34 39 2e 36 32 2f [0-32] 2e 68 74 6d 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "$outputfilepath = @TempDir & \"\\InformationCheck.exe" ascii //weight: 1
        $x_1_4 = "$outputfile = @TempDir & \"\\Details.html" ascii //weight: 1
        $x_1_5 = "inet_forcereload" ascii //weight: 1
        $x_1_6 = "_PERFORMFINALACTION" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

