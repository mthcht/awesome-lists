rule VirTool_Win32_CobalInject_A_2147915425_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CobalInject.A!MTB"
        threat_id = "2147915425"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CobalInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BeaconType" ascii //weight: 1
        $x_1_2 = "Port" ascii //weight: 1
        $x_1_3 = "C2Server" ascii //weight: 1
        $x_1_4 = "ProcInject_Execute" ascii //weight: 1
        $x_1_5 = "HttpPostUri" ascii //weight: 1
        $x_1_6 = "Spawnto_x" ascii //weight: 1
        $n_1_7 = "EventObject.Sha256" ascii //weight: -1
        $n_1_8 = "EventObjectSha256" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

