rule Trojan_Win64_VMPAgent_RP_2147914355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VMPAgent.RP!MTB"
        threat_id = "2147914355"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VMPAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "85"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C:\\Users\\Public\\Pictures\\temp.tmp" ascii //weight: 10
        $x_1_2 = "QQPCLeakScan.exe" ascii //weight: 1
        $x_1_3 = "kwsprotect64.exe" ascii //weight: 1
        $x_1_4 = "KvMonXP.exe" ascii //weight: 1
        $x_1_5 = "rsdelaylauncher.exe" ascii //weight: 1
        $x_1_6 = "360Tray.exe" ascii //weight: 1
        $x_10_7 = "CreateRemoteThread + ExitProcess" ascii //weight: 10
        $x_10_8 = "Eip Modification + ExitProcess" ascii //weight: 10
        $x_10_9 = "Inject shellcode" ascii //weight: 10
        $x_10_10 = "Crash with VirtualProtectEx" ascii //weight: 10
        $x_10_11 = "Crash with WriteProcessMemory" ascii //weight: 10
        $x_10_12 = "Crash with DuplicateHandle" ascii //weight: 10
        $x_10_13 = "Crash with CreateJobObject, AssignProcessToJobObject, TerminateJobObject" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

