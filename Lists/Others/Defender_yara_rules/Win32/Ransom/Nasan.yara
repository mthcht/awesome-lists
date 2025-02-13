rule Ransom_Win32_Nasan_A_2147721309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nasan.A!rsm"
        threat_id = "2147721309"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nasan"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ff 00 00 00 66 33 cf 66 23 c8 0f b6 04 f5 ?? ?? ?? ?? 66 33 c8 47 66 89 0c 53 66 3b 3c f5 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {d1 e8 35 20 83 b8 ed eb 02 d1 e8 4a 75 ?? 89 01 47 83 c1 04 81 ff 00 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {83 c9 ff 85 db 74 ?? 0f b6 04 2e 33 c1 c1 e9 08 25 ff 00 00 00 33 0c 85 ?? ?? ?? ?? 46 3b f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Nasan_B_2147723289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Nasan.B!bit"
        threat_id = "2147723289"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Nasan"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 34 8b 04 f5 ?? ?? ?? 00 0f b7 d7 66 0f be 0c 10 b8 ff 00 00 00 66 33 cf 66 23 c8 0f b6 04 f5 ?? ?? ?? 00 66 33 c8 47 66 89 0c 53 66 3b 3c f5 ?? ?? ?? 00 72 cc}  //weight: 1, accuracy: Low
        $x_1_2 = {73 24 8b 04 f5 ?? ?? ?? 00 0f b7 ca 8a 04 08 32 04 f5 ?? ?? ?? 00 32 c2 42 88 04 39 66 3b 14 f5 ?? ?? ?? 00 72 dc}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 07 59 e8 b8 05 00 00 6a 0e 8d 54 24 10 59 e8 64 05 00 00 8d 44 24 28 50 ff 15 ?? ?? ?? 00 33 ed 45 85 c0 74 13 8d 4c 24 0c 51 50 ff 15 ?? ?? ?? 00 85 c0 74 03 55 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

