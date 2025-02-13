rule TrojanDownloader_Win32_CobaltStrike_N_2147839351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CobaltStrike.N!MSR"
        threat_id = "2147839351"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "enhanced-google.com" ascii //weight: 1
        $x_1_2 = "Control_RunDLL \"C:\\ProgramData\\AxlnstSV\\xlsrd.cpl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_CobaltStrike_GV_2147920883_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/CobaltStrike.GV!MTB"
        threat_id = "2147920883"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_2_2 = "://0x1.social" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

