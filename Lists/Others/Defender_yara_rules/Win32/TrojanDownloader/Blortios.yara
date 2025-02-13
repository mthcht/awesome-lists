rule TrojanDownloader_Win32_Blortios_C_2147651021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Blortios.C"
        threat_id = "2147651021"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Blortios"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "file.aspx?file=2" ascii //weight: 2
        $x_2_2 = "blogdecharutos.com" ascii //weight: 2
        $x_2_3 = "User-Agent: ksp/WS" ascii //weight: 2
        $x_1_4 = "Referer: http://www.google.com" ascii //weight: 1
        $x_1_5 = "ProgramData\\WLSetup" ascii //weight: 1
        $x_1_6 = "VbPQRSTU+ABCDEFGc2/5678fghijstu01Mkl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Blortios_E_2147656381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Blortios.E"
        threat_id = "2147656381"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Blortios"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Clients\\StartMenuInternet\\IEXPLORE.EXE\\shell\\open\\command\\" wide //weight: 1
        $x_1_2 = {64 77 6e 6c 64 72 [0-1] 50 72 6f 63 65 73 73 43 6f 6d 70 6c 65 74 65 64}  //weight: 1, accuracy: Low
        $x_1_3 = "VbPQRSTU+ABCDEFGc2/5678fghijstu01Mkl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

