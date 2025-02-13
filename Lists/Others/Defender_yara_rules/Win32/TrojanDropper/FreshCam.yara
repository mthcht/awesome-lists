rule TrojanDropper_Win32_FreshCam_A_2147925346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/FreshCam.A!dha"
        threat_id = "2147925346"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "FreshCam"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {56 31 c0 85 d2 74 1d 0f b6 31 41 4a 69 f6 3c fd 14 31 0f af f6 c1 c6 10 31 c6 0f af f6 c1 c6 10 89 f0 eb df 5e c3}  //weight: 100, accuracy: High
        $x_100_2 = {81 fb 77 dd 41 b1 8b 5e 08 75}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

