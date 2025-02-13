rule Trojan_Win32_Solorigate_A_2147771191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Solorigate.A!!Solorigate.A!dha"
        threat_id = "2147771191"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Solorigate"
        severity = "Critical"
        info = "Solorigate: an internal category used to refer to some threats"
        info = "A: an internal category used to refer to some threats"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 c8 45 0f b6 4c 0a 30 48 [0-48] 89 ?? 41 31 c0 45 88 04 0a 48 83 c1 01 45 89 c8 41 39 cb 7f ?? 31 c0 48 81 c4 ?? ?? ?? ?? 5b 5e 5f c3}  //weight: 1, accuracy: Low
        $x_1_2 = {48 b8 53 4f 46 54 57 41 52 45 c7 44 24 60 66 74 5c 43 c6 44 24 66 00 48 89 44 24 50 48 b8 5c 4d 69 63 72 6f 73 6f 4c 8d 44 24 48 48 89 44 24 58 b8 54 46 00 00 ?? 89 ea 66 89 44 24 64 48 c7 c1 01 00 00 80 ff 15 ?? ?? ?? ?? 85 c0 74 ?? 31 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {09 05 00 d8 0f 85 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 41 b8 04 00 00 00 48 89 ?? c7 44 24 70 4a 46 49 46 c6 44 24 74 00 e8 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? c6 05 ?? ?? 05 00 6a c6 05 ?? ?? 05 00 70 c6 05 ?? ?? 05 00 65 c6 05 ?? ?? 05 00 67 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

