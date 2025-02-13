rule HackTool_Win32_SystemSchtaskFromPublicUser_A_2147773774_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SystemSchtaskFromPublicUser.A"
        threat_id = "2147773774"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SystemSchtaskFromPublicUser"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "schtasks.exe" wide //weight: 10
        $x_1_2 = "/Create" wide //weight: 1
        $x_1_3 = "/SC ONLOGON" wide //weight: 1
        $x_1_4 = "/RU system" wide //weight: 1
        $x_1_5 = "C:\\Users\\Public\\" wide //weight: 1
        $n_10_6 = "automate" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

