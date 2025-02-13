rule TrojanSpy_Win32_Upolid_A_2147717338_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Upolid.A"
        threat_id = "2147717338"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Upolid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WinShellUpdate.lnk" wide //weight: 1
        $x_1_2 = "/screenShot" wide //weight: 1
        $x_1_3 = "tasklist > \"" wide //weight: 1
        $x_1_4 = "/white_walkers/" wide //weight: 1
        $x_1_5 = "\\sflag.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

