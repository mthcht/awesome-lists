rule VirTool_Win32_Feline_A_2147763586_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Feline.A!MTB"
        threat_id = "2147763586"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Feline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xc/server.forward" ascii //weight: 1
        $x_1_2 = "xc/server.exit" ascii //weight: 1
        $x_1_3 = "xc/server.handleCmd" ascii //weight: 1
        $x_1_4 = "xc/server.sendReader" ascii //weight: 1
        $x_1_5 = "yamux" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Feline_A_2147763586_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Feline.A!MTB"
        threat_id = "2147763586"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Feline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xc/server.(*augWriter).Write" ascii //weight: 1
        $x_1_2 = "xc/server.lfwd" ascii //weight: 1
        $x_1_3 = "xc/server.handleCmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Feline_A_2147763586_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Feline.A!MTB"
        threat_id = "2147763586"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Feline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xc/server/server.go" ascii //weight: 1
        $x_1_2 = "xc/client/client_windows.go" ascii //weight: 1
        $x_1_3 = "xc/client/client.go" ascii //weight: 1
        $x_1_4 = "xc/vulns/vulns_windows.go" ascii //weight: 1
        $x_1_5 = "xc/shell.StartSSHServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Feline_A_2147763586_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Feline.A!MTB"
        threat_id = "2147763586"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Feline"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xc/load.go" ascii //weight: 1
        $x_1_2 = "syscall/zsyscall_windows.go" ascii //weight: 1
        $x_1_3 = "main.Bake" ascii //weight: 1
        $x_1_4 = {31 c0 48 8b 8c 24 50 05 00 00 87 81 28 03 00 00 b8 01 00 00 00 f0 0f c1 81 00 03 00 00 48 8b 05 30 39 52 00 48 89 04 24 48 8b 44 24 48 48 89 44 24 08 e8 ?? ?? ?? ?? 48 8b 05 ce 39 52 00 48 89 04 24 48 8b 44 24 48 48 89 44 24 08 e8 ?? ?? ?? ?? 48 8b ac 24 40 05 00 00 48 81 c4 48 05 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {48 89 6c 24 30 48 8d ?? ?? ?? 48 8b 44 24 48 48 89 04 24 48 8b 44 24 40 48 89 44 24 08 e8 ?? ?? ?? ?? 48 8b ?? ?? ?? ?? ?? 48 89 04 24 48 c7 44 24 08 00 00 00 00 48 8b 44 24 40 48 89 44 24 10 48 c7 44 24 18 00 30 00 00 48 c7 44 24 20 04 00 00 00 e8 ?? ?? ?? ?? 48 8b 44 24 28 48 89 44 24 50 48 8b 6c 24 30 48 83 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

