rule Trojan_Win32_Gearclop_B_2147624090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gearclop.gen!B"
        threat_id = "2147624090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gearclop"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 ad 86 c4 66 33 05 ?? ?? 40 00 66 ff 05 ?? ?? 40 00 66 ab e2 ea b8 e8 00 00 00 50 6a 40 ff 54 24 24 85 c0 0f 84 f8 00 00 00 be 02 11 40 00 8b f8 b9 e8 00 00 00 f3 a4 ff e0 8b 3c 24 03 7f 3c 8b f7 8b 7f 34 8b 76 50 03 f7 57 8b 44 24 08 ff d0 68 00 80 00 00 6a 00 57 8b 44 24 14 ff d0 6a 40 68 00 30 00 00 68 00 00 01 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gearclop_A_2147624262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gearclop.gen!A"
        threat_id = "2147624262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gearclop"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 ad 86 c4 66 33 05 ?? ?? ?? ?? 66 ff 05 ?? ?? ?? ?? 66 ab e2 ea}  //weight: 2, accuracy: Low
        $x_1_2 = {ff e0 8b 3c 24 03 7f 3c 8b f7 8b 7f 34 8b 76 50}  //weight: 1, accuracy: High
        $x_1_3 = {8b 04 24 03 40 3c 8b 40 28 03 c3 83 c4 ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Gearclop_C_2147633864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gearclop.gen!C"
        threat_id = "2147633864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gearclop"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {24 0f c6 06 61 00 06 c1 c0 04 46 e2 f3}  //weight: 1, accuracy: High
        $x_1_2 = {83 45 ec 03 83 45 f0 03 8d 45 e4 50 e8 ?? ?? ?? ?? 6a 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

