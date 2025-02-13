rule Trojan_Win64_AVKiller_EC_2147919990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/AVKiller.EC!MTB"
        threat_id = "2147919990"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "AVKiller"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EvilBytecode/GoDefender/AntiDebug/CheckBlacklistedWindowsNames.init" ascii //weight: 1
        $x_1_2 = "EvilBytecode/GoDefender/AntiDebug/IsDebuggerPresent.IsDebuggerPresent1" ascii //weight: 1
        $x_1_3 = "AntiDebug/KillBadProcesses/KillBadProcesses.go" ascii //weight: 1
        $x_1_4 = "AntiVirtualization/UsernameCheck/UsernameCheck.go" ascii //weight: 1
        $x_1_5 = "AntiVirtualization/VMWareDetection/vmwaredetection.go" ascii //weight: 1
        $x_1_6 = "AntiVirtualization/VirtualboxDetection/virtualboxdetection.go" ascii //weight: 1
        $x_1_7 = "MainGo/adr.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

