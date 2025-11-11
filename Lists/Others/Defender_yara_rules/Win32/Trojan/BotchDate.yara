rule Trojan_Win32_BotchDate_A_2147957203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BotchDate.A!dha"
        threat_id = "2147957203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BotchDate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 ?? ?? 20 00 2f 00 46 00 20 00 2f 00 43 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 54 00 4e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 00 73 00 63 00 20 00 6d 00 69 00 6e 00 75 00 74 00 ?? ?? 20 00 2f 00 4d 00 4f 00 20 00 31 00 20 00 2f 00 54 00 52 00}  //weight: 1, accuracy: Low
        $x_1_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 ?? 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {69 20 6c 6f 76 65 20 ?? 6d 65 72 69 63 61}  //weight: 1, accuracy: Low
        $x_10_5 = {6a 00 6a 00 6a 00 6a 00 6a 00 8d 45 ?? 50 6a 00 6a 00 8d 4d ?? 51 8d 55 ?? 52 ff 55 ?? 8b 4d ?? 8d 45 ?? 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 51 6a 40 8d 55 ?? 52 ff d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

