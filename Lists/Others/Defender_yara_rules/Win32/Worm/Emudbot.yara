rule Worm_Win32_Emudbot_A_2147647667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Emudbot.A"
        threat_id = "2147647667"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Emudbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 4c 6f 67 2e 70 68 70 3f 64 6c 3d 90 02 04 26 6c 6f 67 3d}  //weight: 1, accuracy: High
        $x_1_2 = "%~d0\\autorun.vbs" ascii //weight: 1
        $x_1_3 = "shell\\Auto\\command=autorun.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

