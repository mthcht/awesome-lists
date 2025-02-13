rule TrojanDropper_Win32_ProcessInjector_A_2147602090_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/ProcessInjector.A"
        threat_id = "2147602090"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessInjector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "73"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "\\Program Files\\Internet Explorer\\IEXPLORE.EXE" ascii //weight: 10
        $x_10_3 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 10
        $x_10_4 = "SeDebugPrivilege" ascii //weight: 10
        $x_10_5 = "DisableRegistryTools" ascii //weight: 10
        $x_10_6 = "WriteProcessMemory" ascii //weight: 10
        $x_10_7 = "NtAllocateVirtualMemory" ascii //weight: 10
        $x_1_8 = "KvMon.exe" ascii //weight: 1
        $x_1_9 = "cmd.exe /c del " ascii //weight: 1
        $x_1_10 = "Winsta0\\Default" ascii //weight: 1
        $x_1_11 = "system32\\userinit.exe," ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

