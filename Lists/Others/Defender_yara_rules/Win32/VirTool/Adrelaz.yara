rule VirTool_Win32_Adrelaz_A_2147827766_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Adrelaz.A!MTB"
        threat_id = "2147827766"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Adrelaz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ADFSRelay/pkg/ntlm.DecodeMessage" ascii //weight: 1
        $x_1_2 = "spew/bypass.go" ascii //weight: 1
        $x_1_3 = "praetorian-in/ADFSRelay/pkg/cookies" ascii //weight: 1
        $x_1_4 = "ADFSRelay/pkg/ntlm/ntlm.go" ascii //weight: 1
        $x_1_5 = "ADFSRelay/ADFSRelay.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

