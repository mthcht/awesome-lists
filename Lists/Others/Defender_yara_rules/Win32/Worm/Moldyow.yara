rule Worm_Win32_Moldyow_A_2147617629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Moldyow.A"
        threat_id = "2147617629"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Moldyow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {53 50 49 36 34 2e 64 6c 6c ?? 55 6e 48 6f}  //weight: 4, accuracy: Low
        $x_1_2 = {5c 69 6d 65 5c [0-3] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = "ws2_42.dll" ascii //weight: 1
        $x_2_4 = {8a 94 07 94 01 00 00 69 c9 06 03 00 00 03 c8 40}  //weight: 2, accuracy: High
        $x_4_5 = {de de 99 f7 7d 10 8b 45 0c 0f be 04 02 33 41 04 99 f7 fb}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Moldyow_A_2147617629_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Moldyow.A"
        threat_id = "2147617629"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Moldyow"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {80 7c 01 07 3b 75 0e 80 7c 01 09 74 75 07 80 7c 01 0b 3b 74 07 41 3b ca 72 d2 eb 5c 03 c1 c6 40 01 90 c6 00 90}  //weight: 4, accuracy: Low
        $x_4_2 = {80 39 68 75 2a 80 79 05 ff 75 24 80 79 06 15 75 1e 80 79 0b e9 75 18 39 41 07 75 13 8b 46 34 8d 44 10 10}  //weight: 4, accuracy: High
        $x_4_3 = {83 f9 02 aa 75 0b 8d 45 f8 50 68 ?? ?? ?? ?? eb 35 83 f9 03 75 0b 8d 45 f8 50 68 ?? ?? ?? ?? eb 25 83 f9 05 75 0b 8d 45 f8 50 68 ?? ?? ?? ?? eb 15}  //weight: 4, accuracy: Low
        $x_1_4 = "shell\\Open\\Command=.\\%s -o" ascii //weight: 1
        $x_1_5 = "%4d-%02d-%02d %02d:%02d:%02d" ascii //weight: 1
        $x_1_6 = "version %d.%d %s (Build %d)" ascii //weight: 1
        $x_1_7 = "CDROM(%s)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

