rule TrojanDownloader_Win32_Wobotork_A_2147686266_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Wobotork.A"
        threat_id = "2147686266"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Wobotork"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 0f 00 00 00 f7 f9 83 7d ?? 10 8b 45 ?? 73 03 8d 45 ?? 8a 5c 10 01 8d 75 ?? e8 ?? ?? ?? ?? 4f 75 d8}  //weight: 1, accuracy: Low
        $x_1_2 = "Set oShell = WScript.CreateObject(\"WScript.Shell\"):oShell.Exec(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

