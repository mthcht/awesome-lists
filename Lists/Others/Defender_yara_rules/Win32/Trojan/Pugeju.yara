rule Trojan_Win32_Pugeju_A_2147600456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pugeju.A"
        threat_id = "2147600456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pugeju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 4d 49 43 72 [0-6] 75 [0-20] (e9|eb) [0-20] 0f 6e 45 14}  //weight: 1, accuracy: Low
        $x_1_2 = {68 fa 1e 00 00 50 ff 77 04 e8 ?? ?? 00 00 20 00 [0-18] 0f 6e ?? fc 0f 7e [0-10] 05 06 01 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 6e e8 0f 7e 2d 0f 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? e9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 85 d4 fc ff ff 07 00 01 00 [0-3] ff b5 c0 fc ff ff [0-3] ff 75 b0 [0-3] 68 ?? ?? ?? 00 ff 35 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_5 = {68 0d 0a 00 00 0f ?? ?? 0f ?? ?? [0-6] 8d 05 ?? ?? ?? 00 [0-3] 6a 00 50 6a 02 ?? 53}  //weight: 1, accuracy: Low
        $x_1_6 = {b8 51 55 49 54 [0-3] ab [0-3] b8 0d 0a 00 00 [0-3] 66 ab [0-3] 5f [0-3] 6a 00 6a 06 ff 75 cc ff 75 c0 e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_7 = {3d 4d 49 43 72 75 ?? [0-3] 61 [0-3] eb}  //weight: 1, accuracy: Low
        $x_1_8 = {83 3d 8f 09 41 00 00 74 ?? 68 ?? 10 40 00 (0d ?? ??|b8 ?? ?? 40 00) 74 05 e9 ?? ?? 00 00 68 ?? 10 40 00}  //weight: 1, accuracy: Low
        $x_1_9 = {83 3d 7f 09 41 00 00 74 ?? 68 ?? 10 40 00 b8 ?? ?? 40 00 35 ?? ?? 40 00 75 05 e9 ?? ?? 00 00 68 ?? 10 40 00}  //weight: 1, accuracy: Low
        $x_1_10 = {74 4d 68 59 10 40 00 68 ?? ?? 40 00 68 ?? ?? 40 00 68 ?? ?? 40 00 68 ?? ?? 40 00 68 ?? ?? 40 00 68 ?? ?? 40 00 e9 ?? ?? 00 00 68 7c 10 40 00 07 00 83 3d ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Pugeju_C_2147605460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pugeju.C"
        threat_id = "2147605460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pugeju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Inside EntryPoint" ascii //weight: 1
        $x_1_2 = "listen" ascii //weight: 1
        $x_1_3 = "getsockname" ascii //weight: 1
        $x_1_4 = "OpenSCManagerA" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
        $x_10_6 = {0d 0a 00 3a 00 64 65 6c 20 00 69 66 20 65 78 69 73 74 20 00 20 67 6f 74 6f 20 00 64 65 6c 20 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 00 69 63 66}  //weight: 10, accuracy: High
        $x_1_7 = {c3 50 51 53 52 9c 66 8c c8 66 83 f8 1b 75 3b 33 c0 0f a2 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

