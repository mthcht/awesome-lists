rule Trojan_Win32_AceLog_A_2147767194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AceLog.A!dha"
        threat_id = "2147767194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AceLog"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 06 02 00 00 66 89 85 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 68 04 01 00 00 8d 85 ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 08 02 00 00 50 e8 ?? ?? ?? ?? 6a 44}  //weight: 1, accuracy: Low
        $x_1_2 = {52 00 55 00 4e 00 44 00 4c 00 4c 00 33 00 32 00 2e 00 ?? 00 58 00 45 00 20 00 22 00 25 00 73 00 22 00 2c 00 20 00 23 00 31 00 00 00 2a 00 00 00 2e 00 00 00 2e 00 2e 00 00 00}  //weight: 1, accuracy: Low
        $n_10_3 = {52 00 55 00 4e 00 44 00 4c 00 ?? 00 33 00 32 00 2e 00 45 00 58 00 45 00 20 00 22 00 25 00 73 00 22 00 2c 00 20 00 23 00 31 00 00 00 63 6d 64 20 2f ?? 20 44 45 4c 20 00 20 22 00 00}  //weight: -10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_AceLog_B_2147780965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AceLog.B!dha"
        threat_id = "2147780965"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AceLog"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 0f b7 8c 05 ?? ?? ff ff 66 31 8c 05 ?? ?? ff ff 83 c0 08 3d 00 01 00 00 72 b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

