rule Worm_Win32_Shedewbot_A_2147625524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Shedewbot.A"
        threat_id = "2147625524"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Shedewbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NICK [%s][%iH]%s" ascii //weight: 1
        $x_1_2 = "newjoin: %s" ascii //weight: 1
        $x_1_3 = {65 78 65 00 72 61 72 00 47 45 54 20 2f}  //weight: 1, accuracy: High
        $x_1_4 = {53 45 52 56 49 43 45 53 2e 45 58 45 00 00 00 00 57 49 4e 4c 4f 47 4f 4e 2e 45 58 45 00 00 00 00 68 69 64 73 65 72 76 2e 65 78 65 00 00 00 00 00 65 78 70 6c 6f 72 65 72 2e 65 78 65 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {eb 10 5a 4a 33 c9 66 b9 7d 00 00 00 33 c0 64 03 40 30 78 0c 8b}  //weight: 1, accuracy: High
        $x_1_6 = {99 b9 5a 00 00 00 f7 f9 89 55 f8 83 7d f8 1e 7d 26 83 7d fc 00 74 20 83 7d 10 01 75 1a e8}  //weight: 1, accuracy: High
        $x_1_7 = {83 c0 01 89 45 fc 8b 45 fc 3b 45 08 7d 25 e8 ?? ?? ?? ?? 99 b9 1a 00 00 00 f7 f9 83 c2 61}  //weight: 1, accuracy: Low
        $x_1_8 = {83 c4 08 89 45 ?? 66 c7 45 ?? 00 80 c6 45 ?? 30 c6 45 ?? 14 8b 45 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

