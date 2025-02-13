rule TrojanDropper_Win32_VBInject_B_2147611182_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VBInject.B"
        threat_id = "2147611182"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f4 01 f4 ff fe 5d 20 21 2f}  //weight: 1, accuracy: High
        $x_1_2 = {2a 00 5c 00 41 00 43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 5c 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 5c 00 56 00 42 00 36 00 20 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 73 00 5c 00 50 00 61 00 63 00 6b 00 65 00 72 00 5c 00 56 00 [0-4] 5c 00 43 00 6f 00 70 00 69 00 65 00 73 00 5c 00 [0-16] 5c 00 [0-64] 5c 00 74 00 65 00 6d 00 70 00 5c 00 70 00 72 00 6a 00 53 00 74 00 75 00 62 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {09 00 00 00 6b 65 72 6e 65 6c 33 32 00 00 00 00 0e 00 00 00 52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_VBInject_A_2147652489_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/VBInject.gen!A"
        threat_id = "2147652489"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "VBInject"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b9 09 00 00 00 2b 48 ?? c1 e1 04 8b 85 ?? ?? ?? ?? 8b 40 ?? 03 c8 ff 15 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 51 8b 15 ?? ?? ?? ?? 52 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 51 6a 00 ff 15 ?? ?? ?? ?? c7 45 ?? 0b 00 00 00 68 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? dd 9d ?? ?? ?? ?? c7 45 ?? 0c 00 00 00 6a 00 6a 01 6a 01 6a 00 8d 95 ?? ?? ?? ?? 52 6a 10 68 80 08 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {c1 e0 04 8b 8d ?? ?? ?? ?? 8b 49 ?? 03 c8 ff 15 ?? ?? ?? ?? 8d 95 ?? ?? ?? ?? 52 a1 ?? ?? ?? ?? 50 8b 0d ?? ?? ?? ?? 51 e8 ?? ?? ?? ?? 8d 95 ?? ?? ?? ?? 52 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

