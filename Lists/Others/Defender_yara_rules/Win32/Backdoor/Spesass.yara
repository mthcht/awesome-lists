rule Backdoor_Win32_Spesass_A_2147814860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Spesass.A!MTB"
        threat_id = "2147814860"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Spesass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.findPid" ascii //weight: 1
        $x_1_2 = "main.setSilentProcessExit" ascii //weight: 1
        $x_1_3 = "main.setSeDebugPrivilege" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe" ascii //weight: 1
        $x_1_5 = "ReportingMode" ascii //weight: 1
        $x_1_6 = "DumpType" ascii //weight: 1
        $x_1_7 = "LocalDumpFolder" ascii //weight: 1
        $x_1_8 = "GlobalFlag" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

