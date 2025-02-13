rule TrojanDownloader_Win32_FraudLoad_AN_2147816738_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/FraudLoad.AN!MTB"
        threat_id = "2147816738"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "FraudLoad"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3b ca 75 02 33 c9 8a 1c 29 30 1c 38 40 41 3b c6 7c ee}  //weight: 2, accuracy: High
        $x_1_2 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_3 = "QueryPerformanceCounter" ascii //weight: 1
        $x_1_4 = "GetTickCount" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

