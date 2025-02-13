rule PWS_Win32_Daptdei_A_2147628474_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Daptdei.A"
        threat_id = "2147628474"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Daptdei"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c8 ff eb 18 8b c8 81 e1 ff 00 00 00 0f be d2 33 ca c1 e8 08 46 33 04 8d ?? ?? ?? ?? 8a 16 84 d2 75 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 00 00 00 70 59 3b c2 76 25 8b 48 3c 8b 4c 01 78 81 7c 01 18 00 03 00 00 77 10 05 00 00 ff ff}  //weight: 1, accuracy: High
        $x_1_3 = {74 06 40 80 30 ?? 75 fa}  //weight: 1, accuracy: Low
        $x_1_4 = {75 3d 8d 45 fc 50 68 01 00 00 98 57 c7 45 fc 01 00 00 00 e8 ?? ?? ?? ?? 85 c0 75 23}  //weight: 1, accuracy: Low
        $x_1_5 = {66 39 46 16 0f 85 ?? ?? 00 00 53 83 c6 28 81 3e 55 53 45 52}  //weight: 1, accuracy: Low
        $x_1_6 = "ftpdata=1&user=%s&pass=%s&host=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

