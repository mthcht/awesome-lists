rule HackTool_Win32_Mailpassview_2147571412_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Mailpassview"
        threat_id = "2147571412"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Mailpassview"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "PasswordFox.exe" wide //weight: 5
        $x_5_2 = "VNCPassView.exe" wide //weight: 5
        $x_5_3 = "BulletsPassView.exe" wide //weight: 5
        $x_1_4 = "Password Field" wide //weight: 1
        $x_1_5 = "Password Type" wide //weight: 1
        $x_1_6 = "Passwords List" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

