rule Virus_Win32_Zorg_B_2147710508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Zorg.B!bit"
        threat_id = "2147710508"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Zorg"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "net.exe share $ZORG$=" ascii //weight: 1
        $x_1_2 = {33 c0 a3 a0 77 41 00 8d 45 e4 b9 34 92 40 00 8b 13 e8 7d ae ff ff 8b 45 e4 e8 6d f9 ff ff 83 c3 04 4e 75 dc 81 3d 9c 77 41 00 00 c0 00 00 7e 71 e8 52 fc ff ff eb 35}  //weight: 1, accuracy: High
        $x_1_3 = {7c 1f bf 04 00 00 00 41 2d 00 00 64 a7 81 da b3 b6 e0 0d 73 f2 49 05 00 00 64 a7 81 d2 b3 b6 e0 0d 89 45 e0 89 55 e4 df 6d e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

