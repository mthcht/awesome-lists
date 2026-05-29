rule Trojan_Win32_EchoCreep_Z_2147970499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EchoCreep.Z!MTB"
        threat_id = "2147970499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EchoCreep"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/job" ascii //weight: 1
        $x_1_2 = "/result" ascii //weight: 1
        $x_1_3 = "/me/drive/root:/" ascii //weight: 1
        $x_1_4 = "Host Name" ascii //weight: 1
        $x_1_5 = "graph.microsoft.com" ascii //weight: 1
        $x_1_6 = "User Name" ascii //weight: 1
        $x_1_7 = "get_system_info_json" ascii //weight: 1
        $x_1_8 = "IP Address" ascii //weight: 1
        $x_1_9 = "session" ascii //weight: 1
        $x_1_10 = "Sleep" ascii //weight: 1
        $x_1_11 = "kill" ascii //weight: 1
        $x_1_12 = "heartbeat" ascii //weight: 1
        $x_1_13 = "upload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

