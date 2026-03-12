rule HackTool_Win32_PasswordRecovery_AMTB_2147941419_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PasswordRecovery!AMTB"
        threat_id = "2147941419"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PasswordRecovery"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.SecurityXploded.com" ascii //weight: 1
        $x_1_2 = "NetworkPasswordDecryptor.exe" ascii //weight: 1
        $x_1_3 = "www.PasswordForensics.com" ascii //weight: 1
        $x_1_4 = "Contact@SecurityXploded.com" ascii //weight: 1
        $x_1_5 = "NetworkPasswordDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

