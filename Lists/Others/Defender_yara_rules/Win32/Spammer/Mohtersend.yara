rule Spammer_Win32_Mohtersend_A_2147624516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Mohtersend.A"
        threat_id = "2147624516"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Mohtersend"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MotorSendSpam" ascii //weight: 1
        $x_1_2 = "ExecutaMotorSendSpamShell" ascii //weight: 1
        $x_1_3 = "ExecMethod" ascii //weight: 1
        $x_1_4 = "TXMailShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

