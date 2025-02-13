rule Trojan_Win32_Uphosyfs_2147730106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Uphosyfs"
        threat_id = "2147730106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Uphosyfs"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IFolder.dll" wide //weight: 1
        $x_1_2 = "system32.exe" wide //weight: 1
        $x_1_3 = "IRM.exe" wide //weight: 1
        $x_1_4 = "My_Music.exe" wide //weight: 1
        $x_1_5 = "Photos.exe" wide //weight: 1
        $x_1_6 = "UpFile.exe" wide //weight: 1
        $x_1_7 = "System32.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

