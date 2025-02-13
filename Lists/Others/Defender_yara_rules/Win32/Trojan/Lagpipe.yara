rule Trojan_Win32_Lagpipe_B_2147834813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lagpipe.B!dha"
        threat_id = "2147834813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lagpipe"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "./payload.dll" wide //weight: 1
        $x_1_2 = "\\GLOBAL??\\C:\\OneDriveTemp" wide //weight: 1
        $x_1_3 = "C:\\OneDriveTemp\\Windows\\system32\\DriverStore\\FileRepository\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

