rule TrojanSpy_Win32_Woolerg_A_2147696440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Woolerg.A!dha"
        threat_id = "2147696440"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Woolerg"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "strSTUP = WshShell.SpecialFolders(\"Startup\")" ascii //weight: 1
        $x_1_2 = "set oShellLink = WshShell.CreateShortcut(strSTUP & \"\\WinDefender.lnk\")" ascii //weight: 1
        $x_1_3 = "wlg.dat" ascii //weight: 1
        $x_1_4 = "107.6.181.11" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

