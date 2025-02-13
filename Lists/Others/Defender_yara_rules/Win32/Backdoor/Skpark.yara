rule Backdoor_Win32_Skpark_A_2147809160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Skpark.A!MTB"
        threat_id = "2147809160"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Skpark"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/post" ascii //weight: 1
        $x_1_2 = "last_seen" ascii //weight: 1
        $x_1_3 = "shell_exec" ascii //weight: 1
        $x_1_4 = "SK8PARK" ascii //weight: 1
        $x_1_5 = "macaroon=" ascii //weight: 1
        $x_1_6 = "/stage0" ascii //weight: 1
        $x_1_7 = "/stage1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

