rule PWS_Win32_Delmes_A_2147628515_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Delmes.A"
        threat_id = "2147628515"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Delmes"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {17 00 00 00 6d 61 69 6c 2f 49 6e 62 6f 78 4c 69 67 68 74 2e 61 73 70 78 3f 6e 3d 00}  //weight: 1, accuracy: High
        $x_1_2 = "WshShell.Run \"rundll32.exe shell32.dll,Control_RunDLL" ascii //weight: 1
        $x_1_3 = {bf 01 00 00 00 8b 45 f4 0f b6 5c 38 ff 33 5d e0 3b 5d e4 7f 0b 81 c3 ff 00 00 00 2b 5d e4 eb 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

