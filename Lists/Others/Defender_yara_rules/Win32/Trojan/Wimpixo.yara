rule Trojan_Win32_Wimpixo_A_2147616038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wimpixo.gen!A"
        threat_id = "2147616038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wimpixo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 1a 33 c0 8a c5 32 c3 88 04 16 66 0f b6 02 03 c1 8d 0c 40 c1 e1 04 2b c8 8d 0c 49 8d 0c 89 8d 0c c9 8d 04 48 b9 bf 58 00 00 2b c8 42 4f 75 d0}  //weight: 10, accuracy: High
        $x_1_2 = {8b c8 81 e6 ff ff 00 00 2b f7 8d 04 49 c1 e0 03 2b c1 83 c0 07 46 99 f7 fe 8b c2 03 c7}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 63 6c 6b 25 64 2e 6e 6c 73 00}  //weight: 1, accuracy: High
        $x_10_4 = {81 3c 3e f9 d7 90 eb 75 bd 81 7c 3e 04 2e bb 09 d7 75 b3}  //weight: 10, accuracy: High
        $x_1_5 = "/pset.dat HTTP/1.1" ascii //weight: 1
        $x_2_6 = {81 e5 00 f0 00 00 81 fd 00 30 00 00 75 31 8b 5c 24 10 8b 6c 24 28 43 25 ff 0f 00 00 89 5c 24 10 8b 19 03 c3 8b 1c 30 2b 5d 1c 8b 6c 24 2c 3b dd 75 09 66 81 7c 30 fe c7 05 74 15}  //weight: 2, accuracy: High
        $x_1_7 = {66 c7 44 24 ?? d4 07 66 c7 44 24 ?? 0d 00 66 c7 44 24 ?? 0c 00 66 c7 44 24 ?? 1e 00 66 89 ?? 24 ?? 66 89 ?? 24 ?? ff d6}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 56 3c 66 81 7c 32 14 e0 00 8d 04 32 74 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Wimpixo_B_2147623181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wimpixo.gen!B"
        threat_id = "2147623181"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wimpixo"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 3a f9 d7 90 eb 75 0c 8b 45 ?? 81 78 04 2e bb 09 d7}  //weight: 1, accuracy: Low
        $x_1_2 = {68 67 e0 22 00 8b 45 08 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wimpixo_A_2147633465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wimpixo.A"
        threat_id = "2147633465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wimpixo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 44 24 0c 56 8b 74 24 0c 2b f0 33 d2 8a d5 32 10 88 14 06 66 0f b6 10 03 d1 b9 bf 58 00 00 69 d2 93 31 00 00 2b ca 40 4f 75 e0}  //weight: 5, accuracy: High
        $x_5_2 = {d1 e8 89 45 e8 74 4a 8b 45 08 66 8b 00 8b d8 66 81 e3 00 f0 66 81 fb 00 30 75 25 25 ff 0f 00 00 ff 45 f4 03 01 8b 1c 30 2b 5f 1c 3b 5d 0c 75 10 0f b7 5c 30 fe 83 eb 4f 81 fb 78 05 00 00 74 15 ff 45 fc 83 45 08 02 8b 45 fc 3b 45 e8 72 b8}  //weight: 5, accuracy: High
        $x_1_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Wimpixo_E_2147638595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wimpixo.E"
        threat_id = "2147638595"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wimpixo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 04 81 3c ?? f9 d7 90 eb 75 ?? 81 7c ?? 04 2e bb 09 d7 75}  //weight: 5, accuracy: Low
        $x_5_2 = {33 d2 8a d5 32 10 88 14 06 66 0f b6 10 03 d1 b9 bf 58 00 00 69 d2 93 31 00 00 2b ca 40 4f 75 e0}  //weight: 5, accuracy: High
        $x_5_3 = {66 c7 44 24 ?? d4 07 66 89 44 24 ?? 66 89 44 24 ?? 66 c7 44 24 ?? 0d 00 66 c7 44 24 ?? 0c 00 66 c7 44 24 ?? 1e 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

