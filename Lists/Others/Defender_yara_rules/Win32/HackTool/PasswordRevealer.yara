rule HackTool_Win32_PasswordRevealer_2147973609_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PasswordRevealer!MTB"
        threat_id = "2147973609"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PasswordRevealer"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Chrome Password Recovery" wide //weight: 1
        $x_1_2 = "ChromePass" wide //weight: 1
        $x_1_3 = "Password File" wide //weight: 1
        $x_1_4 = "NirSoft" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

