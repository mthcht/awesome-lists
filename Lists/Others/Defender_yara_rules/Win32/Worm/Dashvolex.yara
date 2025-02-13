rule Worm_Win32_Dashvolex_A_2147641160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dashvolex.A"
        threat_id = "2147641160"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dashvolex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3.5 Floppy (A:)" wide //weight: 1
        $x_1_2 = "[AutoRun]" wide //weight: 1
        $x_1_3 = "72170903" wide //weight: 1
        $x_1_4 = "passwordDocument" wide //weight: 1
        $x_1_5 = "DriveType" wide //weight: 1
        $x_1_6 = "scripting.filesystemobject" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

