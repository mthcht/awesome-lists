rule Backdoor_Win32_AgentTesla_B_2147792474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/AgentTesla.B!MTB"
        threat_id = "2147792474"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "webcam_link=" ascii //weight: 1
        $x_1_2 = "screen_link=" ascii //weight: 1
        $x_1_3 = "site_username=" ascii //weight: 1
        $x_1_4 = "pcname=" ascii //weight: 1
        $x_1_5 = "logdata=" ascii //weight: 1
        $x_1_6 = "screen=" ascii //weight: 1
        $x_1_7 = "ipadd=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_AgentTesla_B_2147792481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/AgentTesla.B!!AgentTesla.B"
        threat_id = "2147792481"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "AgentTesla"
        severity = "Critical"
        info = "AgentTesla: an internal category used to refer to some threats"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "webcam_link=" ascii //weight: 1
        $x_1_2 = "screen_link=" ascii //weight: 1
        $x_1_3 = "site_username=" ascii //weight: 1
        $x_1_4 = "pcname=" ascii //weight: 1
        $x_1_5 = "logdata=" ascii //weight: 1
        $x_1_6 = "screen=" ascii //weight: 1
        $x_1_7 = "ipadd=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

