rule Backdoor_Win32_Genie_A_2147593298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Genie.gen!A"
        threat_id = "2147593298"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Genie"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile\\GloballyOpenPorts\\List" ascii //weight: 1
        $x_1_3 = "1179:TCP:*:Provides the endpoint mapper and other miscellaneous RPC services." ascii //weight: 1
        $x_1_4 = "Hello my master.I am waiting for your commands." ascii //weight: 1
        $x_1_5 = "Type your password please:>" ascii //weight: 1
        $x_1_6 = "Overflow is not working in my program. Go fuck yourself!!!!!!!!!!!!" ascii //weight: 1
        $x_1_7 = "vshutdown" ascii //weight: 1
        $x_1_8 = "TaskMan and Registry Locks" ascii //weight: 1
        $x_1_9 = "TaskMan and Registry UnLocks" ascii //weight: 1
        $x_1_10 = "DisableRegistryTools" ascii //weight: 1
        $x_1_11 = "DisableTaskMgr" ascii //weight: 1
        $x_1_12 = "-LIBGCCW32-EH-SJLJ-GTHR-MINGW32" ascii //weight: 1
        $x_1_13 = "Genie v1.3 by prncipia.  All Rights Reserved" ascii //weight: 1
        $x_1_14 = "regmont.exe" ascii //weight: 1
        $x_1_15 = "cprog.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (13 of ($x*))
}

