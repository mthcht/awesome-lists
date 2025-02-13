rule Worm_Win32_Gokil_A_2147619429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Gokil.A"
        threat_id = "2147619429"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Gokil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "InfectFlashDisk" ascii //weight: 10
        $x_10_2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ctlmon" wide //weight: 10
        $x_5_3 = "VBA6.DLL" ascii //weight: 5
        $x_5_4 = "GoKiLL" ascii //weight: 5
        $x_1_5 = "Infected by GoKiLL" wide //weight: 1
        $x_1_6 = "Cinta.doc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

