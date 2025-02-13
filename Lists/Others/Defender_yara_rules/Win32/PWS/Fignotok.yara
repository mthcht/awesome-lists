rule PWS_Win32_Fignotok_A_2147627036_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fignotok.A"
        threat_id = "2147627036"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fignotok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 33 d2 b9 05 00 00 00 8b fb f7 f1 8a 44 1e 01 83 c9 ff fe c2 32 d0 33 c0 88 14 1e 46 f2 ae f7 d1 83 c1 fe 3b f1 72 d7}  //weight: 1, accuracy: High
        $x_1_2 = {be 05 00 00 00 f7 f6 83 c2 01 0f be d2 33 ca 8b 45 08 03 45 fc 88 08 eb bb}  //weight: 1, accuracy: High
        $x_1_3 = {6a 05 8b c6 33 d2 59 f7 f1 57 fe c2 32 54 3e 01 88 14 3e 46 e8 ?? ?? ?? ?? 48 59 3b f0 72 e1}  //weight: 1, accuracy: Low
        $x_1_4 = {3d a7 00 00 00 0f 85 ?? ?? 00 00 [0-10] ff 75 fc}  //weight: 1, accuracy: Low
        $x_1_5 = {0f 31 8b d8 0f 31 2b c3 50 83 f8 01 74 f2 58 3d 00 02 00 00 72 09 c7 45 fc 01 00 00 00 eb 07}  //weight: 1, accuracy: High
        $x_1_6 = {64 a1 30 00 00 00 83 c0 68 3e 8b 00 83 f8 70 74 09 c7 45 fc 00 00 00 00 eb 07}  //weight: 1, accuracy: High
        $x_1_7 = {c7 45 ec 1d a7 0d ba 74 3b 83 fa 10 75 02 33 d2 0f be 84 35 48 ff ff ff 0f af 45 ec 31 44 15 b4 8b 45 ec 69 c0 8f bc 00 00 89 45 ec 83 c2 04 8d bd 48 ff ff ff 83 c9 ff 33 c0 46 f2 ae f7 d1 49 3b f1 72 c5}  //weight: 1, accuracy: High
        $x_1_8 = {75 48 80 3e 68 0f 85 ?? ?? 00 00 80 7e 02 74 0f 85 ?? ?? 00 00 80 7e 04 74 0f 85 ?? ?? 00 00 80 7e 06 70 0f 85}  //weight: 1, accuracy: Low
        $x_1_9 = "?action=add&a=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule PWS_Win32_Fignotok_I_2147648734_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fignotok.I"
        threat_id = "2147648734"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fignotok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "?action=add&a=" ascii //weight: 1
        $x_1_2 = {2c 30 80 eb 30 88 5d ?? b3 0a f6 eb 80 ea 30 02 c2 8a d3 f6 ea c1 e9 02 2a 84 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Fignotok_K_2147655631_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Fignotok.K"
        threat_id = "2147655631"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Fignotok"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 83 c0 68 3e 8b 00 83 f8 70 74 09 c7 45 fc 00 00 00 00 eb 07}  //weight: 1, accuracy: High
        $x_1_2 = {0f 31 8b d8 0f 31 2b c3 50 83 f8 01 74 f2 58 3d 00 02 00 00 72 09 c7 45 fc 01 00 00 00 eb 07}  //weight: 1, accuracy: High
        $x_1_3 = {58 59 59 59 6a 04 03 00 c7 45}  //weight: 1, accuracy: Low
        $x_1_4 = {8b f0 8d 78 01 c1 e6 02 31 7d f4 89 84 35 f4 fb ff ff 99 f7 7d f8 8b 45 10 0f be 04 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

