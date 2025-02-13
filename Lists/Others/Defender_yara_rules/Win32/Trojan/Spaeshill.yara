rule Trojan_Win32_Spaeshill_2147707462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spaeshill"
        threat_id = "2147707462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spaeshill"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "GET /games/hill.php?cId=%s" ascii //weight: 3
        $x_3_2 = "GET /games/down.php?cId=%s" ascii //weight: 3
        $x_3_3 = "Projects\\DownWin32\\Release\\DownWin32.pdb" ascii //weight: 3
        $x_1_4 = "\\Intel Chipset.lnk" wide //weight: 1
        $x_1_5 = "DownWin32" wide //weight: 1
        $x_1_6 = "splsrv.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

