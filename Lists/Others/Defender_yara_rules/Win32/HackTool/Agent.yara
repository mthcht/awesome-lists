rule HackTool_Win32_Agent_A_2147641115_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Agent.A"
        threat_id = "2147641115"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Agent"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "zhongzhi.bat" ascii //weight: 1
        $x_1_2 = "ps \\\\" ascii //weight: 1
        $x_1_3 = "vnc.exe -d" ascii //weight: 1
        $x_1_4 = "exec.bat" ascii //weight: 1
        $x_1_5 = "radmin.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

