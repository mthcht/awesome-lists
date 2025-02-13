rule Trojan_Win32_StoneDrill_2147727373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/StoneDrill"
        threat_id = "2147727373"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "StoneDrill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\13930308\\Bot_70_FIX HEADER_FIX_LONGURL 73_StableAndNewProtocol - login all\\Release\\Bot.pdb" ascii //weight: 1
        $x_1_2 = "cmd /c REG DELETE HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v %s /f" ascii //weight: 1
        $x_1_3 = "DLL Failed To Load! coder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

