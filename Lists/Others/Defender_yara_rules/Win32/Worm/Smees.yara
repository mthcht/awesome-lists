rule Worm_Win32_Smees_A_2147593225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Smees.A"
        threat_id = "2147593225"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Smees"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HelloWin" ascii //weight: 1
        $x_1_2 = "IMWindowClass" ascii //weight: 1
        $x_1_3 = "OMFG SOMEONE HAS PUTTED A PICTURE OF YOU ON THIS SITE " ascii //weight: 1
        $x_1_4 = "STUPIDPICTURES" ascii //weight: 1
        $x_1_5 = "C:\\Program Files\\MSN Messenger\\msnmsgr.exe" ascii //weight: 1
        $x_1_6 = "C:\\Program Files\\MSN Messenger\\msrr.exe" ascii //weight: 1
        $x_1_7 = "MSNHiddenWindowClass" ascii //weight: 1
        $x_1_8 = "darn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

