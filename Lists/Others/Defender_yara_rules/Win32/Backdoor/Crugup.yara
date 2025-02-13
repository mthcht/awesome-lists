rule Backdoor_Win32_Crugup_A_2147690721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Crugup.A"
        threat_id = "2147690721"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Crugup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "U29mdHdhcmVcY3BwZ3VydQ==" ascii //weight: 1
        $x_1_2 = "R0g1Sy1HS0w4LUNQUDQtREUyNA==" ascii //weight: 1
        $x_1_3 = "x86kernel2" ascii //weight: 1
        $x_1_4 = "z64_kernel" ascii //weight: 1
        $x_1_5 = "lib/mb.sys" ascii //weight: 1
        $x_1_6 = "lib/md.sys" ascii //weight: 1
        $x_2_7 = {83 ec 04 8d 45 fc ff 00 eb d1 83 3d ?? ?? ?? ?? 06 75 54 c7 45 fc 00 00 00 00 83 7d fc 09 7f 47 8b 45 fc c1 e0 09 05 ?? ?? ?? ?? 89 44 24 08 8b 45 fc c1 e0 09 05 ?? ?? ?? ?? 89 44 24 04 8b 45 fc c1 e0 09 05 ?? ?? ?? ?? 89 04 24 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Crugup_B_2147717360_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Crugup.B"
        threat_id = "2147717360"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Crugup"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 61 64 64 20 72 75 6c 65 20 6e 61 6d 65 3d 22 00}  //weight: 1, accuracy: High
        $x_1_2 = {22 20 70 72 6f 67 72 61 6d 3d 22 00}  //weight: 1, accuracy: High
        $x_1_3 = {22 20 64 69 72 3d 4f 75 74 20 61 63 74 69 6f 6e 3d 61 6c 6c 6f 77 00}  //weight: 1, accuracy: High
        $x_5_4 = {51 75 61 6e 74 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

