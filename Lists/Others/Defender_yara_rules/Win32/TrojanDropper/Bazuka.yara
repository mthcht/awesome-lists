rule TrojanDropper_Win32_Bazuka_2147619891_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Bazuka"
        threat_id = "2147619891"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Bazuka"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Get SSDT" ascii //weight: 10
        $x_10_2 = "ServiceDll" ascii //weight: 10
        $x_10_3 = "\\??\\C:\\" wide //weight: 10
        $x_10_4 = {53 76 63 68 6f 73 74 2e 65 78 65 00 4b 42 39 32 38 30 32}  //weight: 10, accuracy: High
        $x_10_5 = "%SystemRoot%\\System32\\svchost.exe -k " ascii //weight: 10
        $x_1_6 = "ZwQuerySystemInformation" ascii //weight: 1
        $x_1_7 = "PsTerminateSystemThread" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileA" ascii //weight: 1
        $x_1_9 = "InternetReadFile" ascii //weight: 1
        $x_1_10 = "SeDebugPrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

