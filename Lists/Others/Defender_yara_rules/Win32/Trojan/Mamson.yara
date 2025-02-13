rule Trojan_Win32_Mamson_RW_2147796506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mamson.RW!MTB"
        threat_id = "2147796506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mamson"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "G:\\NetPCClient\\WinNetClient\\net-client\\brbuild\\Release\\PDB\\BonreeKingKong.pdb" ascii //weight: 1
        $x_1_2 = "DisableProxy" ascii //weight: 1
        $x_1_3 = "GetStartupInfoA" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "CpuAndMemoryMonitor::ClearData" ascii //weight: 1
        $x_1_6 = "_crt_debugger_hook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

