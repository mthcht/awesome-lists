rule Worm_Win32_Vesenlosow_A_2147644445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Vesenlosow.A"
        threat_id = "2147644445"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Vesenlosow"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "shin\\sss.col" wide //weight: 1
        $x_1_2 = "shin\\ss.col" wide //weight: 1
        $x_1_3 = "\\msmm.exe /p" wide //weight: 1
        $x_1_4 = "Startups\\desktop.ini" wide //weight: 1
        $x_1_5 = {59 00 61 00 68 00 6f 00 6f 00 2e 00 4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 ?? ?? ?? ?? ?? ?? 59 00 61 00 68 00 6f 00 6f 00 21 00 4d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_6 = "time -- and I'm pretty sure there is none." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

