rule HackTool_Win32_SanmaoSMTPMailCracker_A_2147707439_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SanmaoSMTPMailCracker.A"
        threat_id = "2147707439"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SanmaoSMTPMailCracker"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sanmao SMTP Mail Cracker" wide //weight: 1
        $x_1_2 = "EHLO ylmf-pc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

