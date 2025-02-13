rule Trojan_Win32_Salgorea_A_2147694026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salgorea.A!dha"
        threat_id = "2147694026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salgorea"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 fe 80 96 98 00 7c df be 02 00 00 00 33 c9 81 ee ?? ?? ?? ?? 8b ff 8d 84 0e ?? ?? ?? ?? 99 bf 05 00 00 00 f7 ff 41 30 91 ?? ?? ?? ?? 81 f9 60 1e 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 92 48 52 85 75 09 b0 01 a2 ?? ?? ?? ?? 5d c3 3d 4c f7 5d b0}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 0e 33 c8 81 e1 ff 00 00 00 4a 46 81 f9 00 01 00 00 73 0a c1 e8 08 33 04 8d ?? ?? ?? ?? 85 d2 75 dd}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 00 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 2f 00 6d 00 69 00 6e 00 20 00 22 00 22 00 20 00 22 00}  //weight: 1, accuracy: High
        $x_1_5 = "rundll32.exe /safemode" wide //weight: 1
        $x_1_6 = {48 42 66 89 01 0f b7 84 55 fc f7 ff ff 8d 8c 55 fc f7 ff ff 33 db 66 3b d8 75 e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Salgorea_B_2147707179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salgorea.B!dha"
        threat_id = "2147707179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salgorea"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 f0 80 4f 12 00 6a 20 6a 00 8d 45 c8 50 e8 ?? ?? ?? ?? 83 c4 0c c7 45 cc 00 00 00 00 c7 45 d0 01 00 00 00 c7 45 d4 06 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 42 74 89 01 8b 4d e8 83 79 34 00 0f 82 a9 01 00 00 8b 55 e8 81 7a 34 00 80 84 1e}  //weight: 1, accuracy: High
        $x_1_3 = {81 bd dc fe ff ff 72 b5 07 00 0f 84 36 05 00 00 81 bd dc fe ff ff c5 57 05 00}  //weight: 1, accuracy: High
        $x_1_4 = {81 bd dc fe ff ff 2a 59 0b 00 0f 84 8b 00 00 00 81 bd dc fe ff ff 37 82 0b 00}  //weight: 1, accuracy: High
        $x_1_5 = {38 00 32 00 36 00 33 00 30 00 34 00 31 00 31 00 65 00 35 00 64 00 66 00 30 00 65 00 30 00 63 00 00 00 00 00 4b 00 65 00 72 00 6e 00 00 00 00 00 65 00 6c 00 33 00 32 00}  //weight: 1, accuracy: High
        $x_1_6 = {7b 00 35 00 35 00 46 00 31 00 35 00 34 00 43 00 30 00 2d 00 43 00 44 00 41 00 46 00 2d 00 34 00 35 00 43 00 34 00 2d 00 39 00 41 00 31 00 41 00 2d 00 00 00 38 00 35 00 32 00 46 00 46 00 35 00 31 00 46 00 39 00 35 00 31 00 45 00 00 00 00 00 7d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Salgorea_VRR_2147741068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salgorea.VRR!MTB"
        threat_id = "2147741068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salgorea"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "{E5D8ACFF-6E98-4882-A99A-ECCAFBE8448C}*1947ab8d0a27b5caec806b988f0ee2da*" ascii //weight: 2
        $x_1_2 = "WetucexEllehS" ascii //weight: 1
        $x_1_3 = "aNretupmoCteGmeW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Salgorea_A_2147779264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salgorea.A!MTB"
        threat_id = "2147779264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salgorea"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {f7 9e 05 81 c7 45 ?? 4f 91 31 af c7 45 ?? cf a0 8f dc c7 45 ?? 53 69 47 38 c7 45 ?? f3 c8 bd b6}  //weight: 3, accuracy: Low
        $x_1_2 = {01 23 45 67 c7 85 ?? ?? ?? ?? 89 ab cd ef c7 85 ?? ?? ?? ?? fe dc ba 98}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Salgorea_C_2147783205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salgorea.C!MTB"
        threat_id = "2147783205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salgorea"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 cc cf a0 8f dc c7 45 d0 53 69 47 38}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 c8 4f 91 31 af}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 c4 f7 9e 05 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Salgorea_S_2147783379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salgorea.S!MTB"
        threat_id = "2147783379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salgorea"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 9e 05 81 c7 45 ?? 4f 91 31 af c7 45 ?? cf a0 8f dc c7 45 ?? 53 69 47 38 c7 45 ?? f3 c8 bd b6 c7 45 ?? b9 df 47 8f c7 45 ?? 22 7a f2 ce c7 45 ?? 61 c8 a5 a1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Salgorea_BJ_2147786251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Salgorea.BJ!MTB"
        threat_id = "2147786251"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Salgorea"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 14 30 89 4c 30 04 0f 84}  //weight: 1, accuracy: High
        $x_1_2 = {8b 0c 30 8b 54 30 04 0f c9 0f 84}  //weight: 1, accuracy: High
        $x_1_3 = {0f ca 68 97 b9 44 00 c3}  //weight: 1, accuracy: High
        $x_1_4 = {68 3c 1b 00 00 8b 0d ?? ?? ?? ?? ?? ?? ?? ?? ?? 68 e0 63 a9 00 c7 46 10 ?? ?? ?? ?? 68 a8 c9 0e 10 68 ?? ?? ?? ?? 8a 81 98 00 00 00 0d 9d c3 83 9f 65 32 1e 4f 10 41 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

