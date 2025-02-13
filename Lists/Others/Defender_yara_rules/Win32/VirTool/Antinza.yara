rule VirTool_Win32_Antinza_J_2147903672_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Antinza.J"
        threat_id = "2147903672"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Antinza"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "task_id" ascii //weight: 1
        $x_1_2 = "c2_profile" ascii //weight: 1
        $x_1_3 = "get_tasking" ascii //weight: 1
        $x_1_4 = "tasking_size" ascii //weight: 1
        $x_1_5 = "get_tasking_response" ascii //weight: 1
        $x_1_6 = "Autofac" ascii //weight: 1
        $x_1_7 = "Agent.dll" ascii //weight: 1
        $x_1_8 = "set_keylogs" ascii //weight: 1
        $x_1_9 = "get_socks" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

