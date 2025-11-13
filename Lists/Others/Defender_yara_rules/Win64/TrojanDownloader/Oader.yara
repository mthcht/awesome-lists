rule TrojanDownloader_Win64_Oader_ARAX_2147957444_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Oader.ARAX!MTB"
        threat_id = "2147957444"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Oader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 24 8b d0 0f af d0 ff c0 03 d1 89 54 24 24 3d 50 c3 00 00 7c e8}  //weight: 2, accuracy: High
        $x_1_2 = "RuntimeBroker.exe" ascii //weight: 1
        $x_1_3 = "dllhost.exe" ascii //weight: 1
        $x_1_4 = "taskhostw.exe" ascii //weight: 1
        $x_1_5 = "backgroundTaskHost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

