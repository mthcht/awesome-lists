rule Backdoor_Win32_Thoper_A_2147648161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Thoper.A"
        threat_id = "2147648161"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Thoper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 c3 32 04 16 8b 11 88 04 16 a0 ?? ?? ?? ?? 0c 04 46 a2 ?? ?? ?? ?? 3b 75 0c 0f 8c}  //weight: 2, accuracy: Low
        $x_1_2 = "winsvcfs" ascii //weight: 1
        $x_1_3 = "nateon.duamlive.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Thoper_B_2147651636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Thoper.B"
        threat_id = "2147651636"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Thoper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 83 c0 01 89 45 fc 83 7d fc 04 7d ?? 8b 4d fc 69 c9 ?? ?? ?? ?? 33 d2 66 89 91}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 08 a3 ?? ?? ?? ?? 8b 45 18 50 8b 4d 14 51 8b 55 10 52 8b 45 0c 50 8b 4d 08 51 ff 15 00 5d c2 14 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Thoper_C_2147655307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Thoper.C"
        threat_id = "2147655307"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Thoper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ":SnifferProc" wide //weight: 1
        $x_1_2 = {5b 00 49 00 4e 00 50 00 55 00 54 00 5d 00 3a 00 [0-53] 69 00 6e 00 74 00 65 00 6c 00 2e 00 64 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = "keybd_event" ascii //weight: 1
        $x_1_4 = "SfcIsFileProtected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Thoper_E_2147659061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Thoper.E"
        threat_id = "2147659061"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Thoper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d fc 5a 7e 09 b8 cc cc cc cc ff d0}  //weight: 1, accuracy: High
        $x_1_2 = {83 ec 08 83 3d ?? ?? ?? ?? 00 75 3a 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? 68 ?? ?? ?? ?? 8d 4d f8 e8 ?? ?? ?? ?? 8b c8 e8 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8d 4d f8 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Thoper_F_2147665345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Thoper.F!dha"
        threat_id = "2147665345"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Thoper"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winsta0\\default" wide //weight: 1
        $x_1_2 = "RUNAS" wide //weight: 1
        $x_1_3 = {c1 e1 0c 0f b6 11 83 fa 4d 75 3c 8b 45 ec c1 e0 0c 0f b6 48 01 83 f9 5a 75 2d 8b 55 ec c1 e2 0c 0f b6 42 02 3d 90 00 00 00 75 1c 8b 4d ec c1 e1 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

