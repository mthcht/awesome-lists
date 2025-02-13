rule VirTool_Win32_Thopu_A_2147763588_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Thopu.A!MTB"
        threat_id = "2147763588"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Thopu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reverse-shell/pkg.init" ascii //weight: 1
        $x_1_2 = "reverse-shell/cmd/client/client.go" ascii //weight: 1
        $x_1_3 = "adedayo/reverse-shell/pkg.ShellOut" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

