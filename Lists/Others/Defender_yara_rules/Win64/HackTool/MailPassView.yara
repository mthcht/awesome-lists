rule HackTool_Win64_MailPassView_AMX_2147976055_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/MailPassView.AMX!MTB"
        threat_id = "2147976055"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MailPassView"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 1b 8b 06 8b c8 83 e0 1f c1 f9 05 8b 0c 8d e0 6d 4a 00 c1 e0 06 8d 44 01 04 80 08 20 8b 7d f8}  //weight: 1, accuracy: High
        $x_5_2 = "EaseUS Data Recovery Wizard" ascii //weight: 5
        $x_1_3 = "GetClipboardData" ascii //weight: 1
        $x_1_4 = "LAUNCH_MAIL" ascii //weight: 1
        $x_1_5 = "BROWSER_FAVORTIES" ascii //weight: 1
        $x_1_6 = "Wardow\\AppData\\Local\\Temp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

