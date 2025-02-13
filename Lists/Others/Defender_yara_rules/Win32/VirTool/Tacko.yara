rule VirTool_Win32_Tacko_A_2147823374_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Tacko.A!MTB"
        threat_id = "2147823374"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Tacko"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tacos/pkg/tacos.ReverseShell" ascii //weight: 1
        $x_1_2 = "tacos/pkg/tacos..inittask" ascii //weight: 1
        $x_1_3 = "tacos/tacos_windows.go" ascii //weight: 1
        $x_1_4 = "cmd/tacos/tacos.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

