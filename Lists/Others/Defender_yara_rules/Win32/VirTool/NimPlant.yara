rule VirTool_Win32_NimPlant_A_2147844172_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/NimPlant.A!MTB"
        threat_id = "2147844172"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NimPlant"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "listenerType" ascii //weight: 1
        $x_1_2 = "listenerHost" ascii //weight: 1
        $x_1_3 = "listenerIp" ascii //weight: 1
        $x_1_4 = "listenerPort" ascii //weight: 1
        $x_1_5 = "registerPath" ascii //weight: 1
        $x_1_6 = "sleepJitter" ascii //weight: 1
        $x_1_7 = "taskPath" ascii //weight: 1
        $x_1_8 = "userAgent" ascii //weight: 1
        $x_1_9 = "NimPlant" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

