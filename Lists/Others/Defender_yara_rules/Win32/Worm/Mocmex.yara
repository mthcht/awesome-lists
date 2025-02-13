rule Worm_Win32_Mocmex_A_2147604816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mocmex.gen!A"
        threat_id = "2147604816"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mocmex"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 4b bb 01 00 00 00 8b 45 e4 e8 ?? ?? ff ff 50 8b c3 5a 8b ca 99 f7 f9 8b fa 47 8b 45 e4 0f b6 44 38 ff b9 0a 00 00 00 33 d2 f7 f1 8b 45 fc 0f b6 44 18 ff 33 d0 8d 45 dc e8 ?? ?? ff ff 8b 55 dc 8d 45 e0 e8 ?? ?? ff ff 43 4e 75 ba}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

