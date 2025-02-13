rule HackTool_Win32_NoDefender_A_2147912208_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/NoDefender.A"
        threat_id = "2147912208"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NoDefender"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wsc_proxy.exe" ascii //weight: 1
        $x_1_2 = "loading the wsc_proxy" ascii //weight: 1
        $x_1_3 = "no-defender-loader.pdb" ascii //weight: 1
        $x_1_4 = "runassvc /rpcserver" ascii //weight: 1
        $x_1_5 = "github.com/es3n1n/no-defender" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

