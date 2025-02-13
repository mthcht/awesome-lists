rule Trojan_Win32_Tookibe_A_2147650557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tookibe.A"
        threat_id = "2147650557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tookibe"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {b9 04 00 02 80 89 45 dc 89 45 cc 89 45 bc 89 45 8c 89 4d a4 b8 0a 00 00 00 89 4d b4 bf 08 00 00 00 8d 95 7c ff ff ff 8d 4d bc 89 45 9c 89 45 ac c7 45 84 ?? ?? ?? ?? 89 bd 7c ff ff ff ff d6}  //weight: 5, accuracy: Low
        $x_5_2 = {6a ff 68 00 00 b4 44 68 00 00 87 45 68 00 00 b4 44 52 50 ff 15 ?? ?? ?? ?? 50 56 ff 93 8c 07 00 00}  //weight: 5, accuracy: Low
        $x_1_3 = {73 00 65 00 6e 00 64 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {73 00 6d 00 74 00 70 00 75 00 73 00 65 00 73 00 73 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {46 74 70 46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 00}  //weight: 1, accuracy: High
        $x_1_6 = {33 00 32 00 5c 00 64 00 65 00 61 00 64 00 31 00 33 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {33 00 32 00 5c 00 64 00 65 00 61 00 64 00 31 00 34 00 2e 00 64 00 61 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {61 00 64 00 6f 00 6c 00 69 00 76 00 72 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 6a 00 6d 00 73 00 2f 00 6d 00 6c 00 62 00 2f 00 73 00 65 00 63 00 75 00 72 00 65 00 4c 00 6f 00 67 00 69 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {63 00 63 00 6f 00 75 00 6e 00 74 00 73 00 2f 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 4c 00 6f 00 67 00 69 00 6e 00 3f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 3d 00 6f 00 72 00 6b 00 75 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Tookibe_B_2147711074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tookibe.B!bit"
        threat_id = "2147711074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tookibe"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 05 00 00 00 c7 45 ?? ?? ?? ?? ?? c7 45 ?? 08 00 00 00 8d 55 ?? 8d 4d ?? ff 15 0c 11 40 00 6a 00 8d 45 ?? 50 ff 15 88 10 40 00 dd 5d ?? 8d 4d ?? ff 15 0c 10 40}  //weight: 1, accuracy: Low
        $x_1_2 = {63 00 6d 00 64 00 20 00 2f 00 63 00 20 00 72 00 65 00 67 00 20 00 61 00 64 00 64 00 20 00 48 00 4b 00 43 00 55 00 5c 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 72 00 75 00 6e 00 20 00 2f 00 76 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 73 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 [0-32] 2e 00 65 00 78 00 65 00 20 00 2f 00 66 00}  //weight: 1, accuracy: Low
        $x_1_3 = "D:\\Windows.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

