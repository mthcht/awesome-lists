rule Worm_Win32_Neeris_C_121219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Neeris.gen!C"
        threat_id = "121219"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Neeris"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 16 8a 09 8b 75 ?? 03 ca 23 c8 03 f3 8a 8c 0d ?? ?? ff ff 30 0e 43 3b 5d ?? 89 5d ?? 72}  //weight: 1, accuracy: Low
        $x_1_2 = {85 db 75 2a 83 f8 20 74 05 83 f8 05 75 20 6a 01 5b 68 98 3a 00 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {68 88 13 00 00 ff 15 ?? ?? ?? ?? 45 83 fd 06 7c ?? 68 30 75 00 00 57 6a 01 53 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Worm_Win32_Neeris_AS_140396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Neeris.AS"
        threat_id = "140396"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Neeris"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Do_voo_doo_On_Your_Moms_Pussy" ascii //weight: 1
        $x_1_2 = "metal-rules-pop-sux" ascii //weight: 1
        $x_10_3 = "LANMAN1.0" ascii //weight: 10
        $x_10_4 = "Content-Type: %s" ascii //weight: 10
        $x_10_5 = {73 61 6e 64 62 6f 78 00 76 6d 77 61 72 65}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Neeris_D_146167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Neeris.gen!D"
        threat_id = "146167"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Neeris"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 db 75 2a 83 f8 20 74 05 83 f8 05 75 20 6a 01 5b 68 98 3a 00 00 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {8d 3c 10 0f b6 01 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 4d 08 8a 84 15 ?? ?? ?? ?? 32 04 39 ff 45 fc 88 07}  //weight: 2, accuracy: Low
        $x_1_3 = {6a 68 ff 15 ?? ?? ?? ?? 6a 04 8d 75 ?? 99 59 f7 f9 85 c0 7e ?? 53 57 8b 3d ?? ?? ?? ?? 8b d8 56 ff 15 ?? ?? ?? ?? 83 f8 02 75}  //weight: 1, accuracy: Low
        $x_1_4 = {00 73 79 73 64 72 76 33 32 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "Cache-Control: no-cache,no-store,max-age=0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Neeris_BK_202405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Neeris.BK"
        threat_id = "202405"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Neeris"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 72 f1 83 3d ?? ?? ?? ?? 00 74 [0-6] f6 d0 88 04 37 56 47}  //weight: 1, accuracy: Low
        $x_1_2 = "no kick me nigga %s" ascii //weight: 1
        $x_1_3 = "p1icka.stp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

