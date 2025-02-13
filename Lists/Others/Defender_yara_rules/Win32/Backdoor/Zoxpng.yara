rule Backdoor_Win32_Zoxpng_A_2147707241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Zoxpng.A!dha"
        threat_id = "2147707241"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Zoxpng"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://%s/%04d-%02d/%04d%02d%02d%02d%02d%02d.png" ascii //weight: 1
        $x_1_2 = "http://%s/imgres?q=" ascii //weight: 1
        $x_1_3 = {42 36 34 3a 5b 25 73 5d [0-16] 53 74 65 70}  //weight: 1, accuracy: Low
        $x_1_4 = {3d 00 10 06 80 76 ?? 8b 4e 04 56 89 4d f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

