rule Backdoor_Win32_OnionDuke_C_2147706157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/OnionDuke.C!dha"
        threat_id = "2147706157"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "OnionDuke"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "upload_slowdown_ms:" ascii //weight: 1
        $x_1_2 = "master_slave_policy:" ascii //weight: 1
        $x_1_3 = "post_per_request_limit_kb:" ascii //weight: 1
        $x_1_4 = "local_limit_mb:" ascii //weight: 1
        $x_1_5 = "mycert: hex(" ascii //weight: 1
        $x_1_6 = "- arg: campaign_id" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

