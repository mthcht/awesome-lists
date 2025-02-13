rule Backdoor_Win32_Mafion_2147596345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mafion"
        threat_id = "2147596345"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mafion"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "44"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Hacker" ascii //weight: 10
        $x_10_2 = "msnmsgr.exe" ascii //weight: 10
        $x_10_3 = "\\WINDOWS\\system32\\drivers\\krnl32.bat" ascii //weight: 10
        $x_10_4 = "del \\WINDOWS\\system32\\service.exe" ascii //weight: 10
        $x_1_5 = "ShutdownMSN" ascii //weight: 1
        $x_1_6 = "KillProcess" ascii //weight: 1
        $x_1_7 = "DisableTaskMgr" ascii //weight: 1
        $x_1_8 = "OpenCD" ascii //weight: 1
        $x_1_9 = "CloseCD" ascii //weight: 1
        $x_1_10 = "set CDAudio door" ascii //weight: 1
        $x_1_11 = "BlockInput" ascii //weight: 1
        $x_1_12 = "SwapMouseButton" ascii //weight: 1
        $x_1_13 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Mafion_A_2147596346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Mafion.gen!A"
        threat_id = "2147596346"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Mafion"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SpecialTrojan" ascii //weight: 10
        $x_10_2 = "C.O.N.N.E.C.T.E.D" ascii //weight: 10
        $x_1_3 = "OpenCD" ascii //weight: 1
        $x_1_4 = "CloseCD" ascii //weight: 1
        $x_1_5 = "MonitorON" ascii //weight: 1
        $x_1_6 = "BlockInput" ascii //weight: 1
        $x_1_7 = "ShutdownMSN" ascii //weight: 1
        $x_1_8 = "ShellExecute" ascii //weight: 1
        $x_1_9 = "FileDownload" ascii //weight: 1
        $x_1_10 = "DisableTaskMgr" ascii //weight: 1
        $x_1_11 = "KillProcess" ascii //weight: 1
        $x_1_12 = "Process to kill" ascii //weight: 1
        $x_1_13 = "Prozess killed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

