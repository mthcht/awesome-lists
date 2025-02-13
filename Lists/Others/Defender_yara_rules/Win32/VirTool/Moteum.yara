rule VirTool_Win32_Moteum_A_2147780137_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Moteum.A!MTB"
        threat_id = "2147780137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Moteum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "postex.SendFile" ascii //weight: 1
        $x_1_2 = "postex.RecvFile" ascii //weight: 1
        $x_1_3 = "postex-tools" ascii //weight: 1
        $x_1_4 = "syscall/windows/zsyscall_windows.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Moteum_A_2147780137_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Moteum.A!MTB"
        threat_id = "2147780137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Moteum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "postex.StartSOCKSProxy" ascii //weight: 1
        $x_1_2 = "postex.handleSOCKS" ascii //weight: 1
        $x_1_3 = "postex.handleSOCKSConnection" ascii //weight: 1
        $x_1_4 = "postex.handleSOCKSCommunication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Moteum_A_2147780137_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Moteum.A!MTB"
        threat_id = "2147780137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Moteum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "postex.CheckShell" ascii //weight: 1
        $x_1_2 = "postex.doGet" ascii //weight: 1
        $x_1_3 = "postex.ReverseTCPShell" ascii //weight: 1
        $x_1_4 = "postex.ReverseUDPShell" ascii //weight: 1
        $x_1_5 = "postex.ReverseShellHTTPS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Moteum_A_2147780137_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Moteum.A!MTB"
        threat_id = "2147780137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Moteum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "postex.Xorify" ascii //weight: 1
        $x_1_2 = "postex-tools/src/xortool/xortool.go" ascii //weight: 1
        $x_1_3 = "postex-tools/src/postex/xor.go" ascii //weight: 1
        $x_1_4 = "http/socks_bundle.go" ascii //weight: 1
        $x_1_5 = "postex/xor.go" ascii //weight: 1
        $x_1_6 = "tools/xortool.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Moteum_A_2147780137_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Moteum.A!MTB"
        threat_id = "2147780137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Moteum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "postex.ShellcodeWindows" ascii //weight: 1
        $x_1_2 = "postex-tools/src/shellcode/shellcode-windows.go" ascii //weight: 1
        $x_1_3 = "postex-tools/src/postex/shellcode-win.go" ascii //weight: 1
        $x_1_4 = "syscall/windows/zsyscall_windows.go" ascii //weight: 1
        $x_1_5 = "postex-tools/postex/shellcode-win.go" ascii //weight: 1
        $x_1_6 = "postex-tools/tools/shellcode-windows.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_Moteum_A_2147780137_5
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Moteum.A!MTB"
        threat_id = "2147780137"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Moteum"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "postex.ShellcodeInjectWindows" ascii //weight: 1
        $x_1_2 = "postex-tools/src/shellcode-inject/shellcode-inject-windows.go" ascii //weight: 1
        $x_1_3 = "postex-tools/src/postex/shellcode-win.go" ascii //weight: 1
        $x_1_4 = "postex-tools/postex/shellcode-win.go" ascii //weight: 1
        $x_1_5 = "postex-tools/tools/shellcode-inject-windows.go" ascii //weight: 1
        $x_1_6 = "/net/http/httpproxy/proxy.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

