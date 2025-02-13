rule Backdoor_Win32_Siluhdur_A_2147608546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Siluhdur.gen!A"
        threat_id = "2147608546"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Siluhdur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 29 bf 01 00 00 00 8b 45 fc 8a 44 38 ff 88 45 fb 8d 45 f4 8a 55 fb 4a e8 ?? ?? ff ff 8b 55 f4 8b c6 e8 ?? ?? ff ff 47 4b 75 dc}  //weight: 1, accuracy: Low
        $x_1_2 = {83 7c c2 08 00 74 24 8b 06 8d 04 80 8b 17 8b 44 c2 08 8b 15 ?? ?? ?? ?? 8b 52 38 e8 ?? ?? ff ff 03 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 06 4b 0f 85 ?? ff ff ff c7 05 ?? ?? ?? ?? 07 00 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

