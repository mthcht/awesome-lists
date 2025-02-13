rule Backdoor_Win32_Qbot_C_2147731261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Qbot.C"
        threat_id = "2147731261"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Qbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d.9S4_Aqum4.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

