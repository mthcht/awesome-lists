rule Trojan_Win32_Plugax_A_2147683197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugax.A"
        threat_id = "2147683197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 8c 3e 10 02 00 00 8a 14 3e 8a 1c 01 32 da 88 1c 01 8b 54 3e 04 40 3b c2 72 ec}  //weight: 2, accuracy: High
        $x_2_2 = {8d 8c 3e 10 02 00 00 8a 14 3e 30 14 01 8b 54 3e 04 40 3b c2}  //weight: 2, accuracy: High
        $x_2_3 = {83 e5 fe 32 db 85 ed 0f 84 ?? ?? ?? ?? 83 fd ff 0f 84 ?? ?? ?? ?? 66 81 7d 00 4d 5a 0f 85 ?? ?? ?? ?? 8b 45 3c 03 c5 81 38 50 45 00 00}  //weight: 2, accuracy: Low
        $x_1_4 = "POST http://%ls:%d/%x HTTP/1.1" ascii //weight: 1
        $x_1_5 = {25 00 54 00 45 00 4d 00 50 00 25 00 5c 00 75 00 69 00 64 00 2e 00 61 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {25 00 25 00 54 00 45 00 4d 00 50 00 25 00 25 00 5c 00 25 00 73 00 5f 00 70 00 2e 00 61 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {43 72 65 61 74 65 50 6c 75 67 69 6e 4f 62 6a 00 25 00 25 00 54}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Plugax_B_2147691712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Plugax.B!dll"
        threat_id = "2147691712"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Plugax"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6c 62 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {85 c0 74 0b 8d 4d e8 51 68 3f 01 0f 00 eb 09 8d 55 e8 52 68 3f 00 0f 00 6a 00 68}  //weight: 1, accuracy: High
        $x_1_3 = {33 c0 8b fb 6a 01 c1 e9 02 f3 ab 8b ca 6a 08 83 e1 03 68 ?? ?? ?? ?? f3 aa 8b 44 24 24 56 50 53 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {83 e1 03 6a 00 f3 aa 8b ce 8b f3 8b c1 8b fa c1 e9 02 f3 a5 8b c8 6a 00 83 e1 03 52 6a 00 6a 00 f3 a4 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

