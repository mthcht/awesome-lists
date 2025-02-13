rule Backdoor_Win32_Lojax_AZXZ_2147730443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lojax.AZXZ!dha"
        threat_id = "2147730443"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lojax"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_40_1 = {6a 52 66 89 85 ?? ?? ?? ?? 58 6a 77 66 89 85 ?? ?? ?? ?? 58 6a 44 66 89 85 ?? ?? ?? ?? 58 6a 72 66 89 85 ?? ?? ?? ?? 58 6a 76 66 89 85 ?? ?? ?? ?? 58 6a 2e 66 89 85 ?? ?? ?? ?? 58 6a 73 66 89 85 ?? ?? ?? ?? 58 6a 79 66 89 85 ?? ?? ?? ?? 58 6a 73}  //weight: 40, accuracy: Low
        $x_10_2 = {4f 53 20 6e 6f 74 20 73 75 70 70 6f 72 74}  //weight: 10, accuracy: Low
        $x_10_3 = {52 65 61 64 20 55 45 46 49 20 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 20 2e 2e}  //weight: 10, accuracy: Low
        $x_10_4 = "Erorr Get SMBIOS." ascii //weight: 10
        $x_10_5 = {43 61 6e 27 74 20 67 65 74 20 73 69 7a 65 20 55 45 46 49 20 69 6d 61 67 65 2e}  //weight: 10, accuracy: Low
        $x_10_6 = {7b 00 38 00 42 00 45 00 34 00 44 00 46 00 36 00 31 00 2d 00 39 00 33 00 43 00 41 00 2d 00 31 00 31 00 44 00 32 00 2d 00 41 00 41 00 30 00 44 00 2d 00 30 00 30 00 45 00 30 00 39 00 38 00 30 00 33 00 32 00 42 00 38 00 43 00 7d 00 90 00 02 00 20 00 53 00 65 00 63 00 75 00 72 00 65 00 42 00 6f 00 6f 00 74 00}  //weight: 10, accuracy: High
        $x_10_7 = {7b 00 7b 00 41 00 46 00 39 00 46 00 46 00 44 00 36 00 37 00 2d 00 45 00 43 00 31 00 30 00 2d 00 34 00 38 00 38 00 41 00 2d 00 39 00 44 00 46 00 43 00 2d 00 36 00 43 00 42 00 46 00 35 00 45 00 45 00 32 00 32 00 43 00 32 00 45 00 7d 00 90 00 02 00 20 00 41 00 63 00 70 00 69 00 47 00 6c 00 6f 00 62 00 61 00 6c 00 56 00 61 00 72 00 69 00 61 00 62 00 6c 00 65 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*))) or
            ((1 of ($x_40_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Lojax_A_2147730444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Lojax.A!dha"
        threat_id = "2147730444"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Lojax"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 8a 00 34 b5 88 06 58 46 40 e2 f4}  //weight: 10, accuracy: High
        $x_10_2 = {6a 04 be 00 10 00 00 56 56 6a 00 53 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 40 6a 00 ff 75 08 ff 15 ?? ?? ?? ?? 40 50 ff 75 08 57 53 ff 15}  //weight: 10, accuracy: Low
        $x_10_3 = "System\\CurrentControlSet\\Services\\rpcnetp" ascii //weight: 10
        $x_10_4 = "rpcnetp.exe" ascii //weight: 10
        $x_10_5 = {68 3f 00 0f 00 33 f6 56 ff 35 ?? ?? ?? ?? 68 02 00 00 80 ff 15 18 10 40 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

