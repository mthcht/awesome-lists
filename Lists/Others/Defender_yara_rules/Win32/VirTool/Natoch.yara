rule VirTool_Win32_Natoch_A_2147827765_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Natoch.A!MTB"
        threat_id = "2147827765"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Natoch"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "distorm3\\distorm3.nim" ascii //weight: 1
        $x_1_2 = "utils\\attacks.nim" ascii //weight: 1
        $x_1_3 = "utils\\inspect.nim" ascii //weight: 1
        $x_1_4 = "patchetw_cmd" ascii //weight: 1
        $x_1_5 = "EtwEventWrite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

