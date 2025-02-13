rule TrojanSpy_Win64_KeyLogger_SK_2147906538_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win64/KeyLogger.SK!MTB"
        threat_id = "2147906538"
        type = "TrojanSpy"
        platform = "Win64: Windows 64-bit platform"
        family = "KeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\WinSysManager.exe" ascii //weight: 2
        $x_2_2 = "D:winlogs.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

