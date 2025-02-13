rule Trojan_Win32_FrostyGoop_A_2147917263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FrostyGoop.A!MTB"
        threat_id = "2147917263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FrostyGoop"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rolfl/modbus" ascii //weight: 1
        $x_1_2 = "main.TaskList.executeCommand" ascii //weight: 1
        $x_1_3 = "main.TargetList.getTargetIpList" ascii //weight: 1
        $x_1_4 = "main.TaskList.getTaskIpList" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

