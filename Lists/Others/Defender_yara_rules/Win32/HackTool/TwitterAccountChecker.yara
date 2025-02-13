rule HackTool_Win32_TwitterAccountChecker_A_2147692527_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/TwitterAccountChecker.A"
        threat_id = "2147692527"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "TwitterAccountChecker"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Twitter Account Checker" ascii //weight: 1
        $x_1_2 = "session%5Busername_or_email%5D={0}&session%5Bpassword%5D={1}&authenticity_token={2}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

