rule HackTool_Win32_PasswordRevealer_2147774129_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PasswordRevealer"
        threat_id = "2147774129"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PasswordRevealer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\NirSoft\\MessenPass" ascii //weight: 1
        $x_1_2 = ".aim.session.password" ascii //weight: 1
        $x_1_3 = "CryptCreateHash" ascii //weight: 1
        $x_1_4 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_5 = "\\mspass\\Release\\mspass.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

