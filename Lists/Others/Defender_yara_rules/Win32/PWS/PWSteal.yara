rule PWS_Win32_PWSteal_B_2147617851_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/PWSteal.B"
        threat_id = "2147617851"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ec 04 66 3d 01 80 0f 85 b9 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "LIBGCCW32-EH-2-SJLJ-GTHR-MINGW32" ascii //weight: 1
        $x_1_3 = {40 7e 35 66 83 ?? ?? 5a 7f 2e 0f b7 ?? ?? 83 c0 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_PWSteal_I_2147626296_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/PWSteal.I"
        threat_id = "2147626296"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Mozilla\\Firefox\\profiles.ini" ascii //weight: 1
        $x_1_2 = "Firefox Stealer" ascii //weight: 1
        $x_1_3 = {50 ff 55 e0 59 85 c0 0f 85 ?? ?? 00 00 ff 55 d8 89 45 bc 83 7d bc 00 0f 84 ?? ?? 00 00 6a 00 6a 01 8b 45 bc 50 ff 55 d4 83 c4 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_PWSteal_K_2147627543_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/PWSteal.K"
        threat_id = "2147627543"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 36 30 73 61 66 65 2e 65 78 65 00 33 36 30 74 72 61 79 2e 65 78 65 00 73 61 66 65 62 6f 78 74 72 61 79 2e 65 78 65 00 67 61 6d 65 2e 65 78 65 00}  //weight: 10, accuracy: High
        $x_10_2 = "CreateToolhelp32Snapshot" ascii //weight: 10
        $x_1_3 = "Host: hi.baidu.com" ascii //weight: 1
        $x_1_4 = "&rank=" ascii //weight: 1
        $x_1_5 = "&pwd=" ascii //weight: 1
        $x_1_6 = "&username=" ascii //weight: 1
        $x_1_7 = "&server=" ascii //weight: 1
        $x_1_8 = "&bankpassword=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_PWSteal_L_2147637551_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/PWSteal.L"
        threat_id = "2147637551"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {85 c0 0f 84 ?? ?? 00 00 b9 10 00 00 00 b8 90 90 90 90 8d bc 24 ?? 00 00 00 f3 ab 8d 84 24 ?? ?? 00 00 8d 8c 24 ?? 00 00 00}  //weight: 10, accuracy: Low
        $x_10_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 43 6f 6e 74 72 6f 6c 5c 4c 73 61 00 00 00 00 4c 73 61 50 69 64}  //weight: 10, accuracy: High
        $x_10_3 = "[%02d/%02d/%d %02d:%02d:%02d]" ascii //weight: 10
        $x_1_4 = {44 6f 6d 61 69 6e 3a [0-5] 25 53}  //weight: 1, accuracy: Low
        $x_1_5 = {55 73 65 72 3a [0-5] 25 53}  //weight: 1, accuracy: Low
        $x_1_6 = {50 61 73 73 77 6f 72 64 3a [0-5] 25 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_PWSteal_O_2147648400_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/PWSteal.O"
        threat_id = "2147648400"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "c3ZjaG9zdC5leGU=" wide //weight: 5
        $x_5_2 = "XFBvbGljaWVzXFN5c3RlbSAvdiBEaXNhYmxlVGFza01nciAvdCBSRUdfRFdPUkQgL2QgMSAvZg" wide //weight: 5
        $x_5_3 = "XFBvbGljaWVzXFN5c3RlbSAvdiBEaXNhYmxlUmVnaXN0cnlUb29scyAvdCBSRUdfRFdPUkQgL2QgMSAvZg" wide //weight: 5
        $x_1_4 = "CD Key :" wide //weight: 1
        $x_1_5 = "Steam Username :" wide //weight: 1
        $x_1_6 = "Computer Name :" wide //weight: 1
        $x_1_7 = "OS Product Key :" wide //weight: 1
        $x_1_8 = "[TAB]" wide //weight: 1
        $x_1_9 = "[DEL]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_PWSteal_P_2147656538_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/PWSteal.P"
        threat_id = "2147656538"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\SoulShaker\\Documents\\ClownStealerSource\\" wide //weight: 1
        $x_1_2 = {5c 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 5c 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 5c 00 [0-6] 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 73 00 2e 00 69 00 6e 00 69 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\signons3.txt" wide //weight: 1
        $x_1_4 = "PK11SDR_Decrypt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_PWSteal_Q_2147725143_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/PWSteal.Q!bit"
        threat_id = "2147725143"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cb b8 01 00 00 00 d3 e0 50 8b c6 5a 8b ca 99 f7 f9 8b f8 8b cb b8 01 00 00 00 d3 e0 50 8b c6 5a 8b ca 99 f7 f9 8b f2}  //weight: 1, accuracy: High
        $x_1_2 = {46 81 e6 ff 00 00 00 03 84 b5 ?? ?? ?? ?? 25 ff 00 00 00 8a 9c b5 ?? ?? ?? ?? 88 5d ?? 8b 9c 85 ?? ?? ?? ?? 89 9c b5 ?? ?? ?? ?? 33 db 8a 5d ?? 89 9c 85 ?? ?? ?? ?? 8b 9c b5 ?? ?? ?? ?? 03 9c 85 ?? ?? ?? ?? 81 e3 ff 00 00 00 8a 9c 9d ?? ?? ?? ?? 30 19 41 4a 75}  //weight: 1, accuracy: Low
        $x_1_3 = "/c timeout 1 & del" wide //weight: 1
        $x_1_4 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_PWSteal_R_2147725171_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/PWSteal.R!bit"
        threat_id = "2147725171"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "PWSteal"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Coins" wide //weight: 1
        $x_1_2 = "[Programms]" wide //weight: 1
        $x_1_3 = "Passwords.txt" ascii //weight: 1
        $x_1_4 = "reportdata=<info" ascii //weight: 1
        $x_1_5 = "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0" wide //weight: 1
        $x_2_6 = {83 ef 08 8b cf 8b 5d ?? d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b 45 ?? 5a 8b ca 99 f7 f9 89 55}  //weight: 2, accuracy: Low
        $x_2_7 = {46 81 e6 ff 00 00 00 03 84 b5 ?? ?? ?? ?? 25 ff 00 00 00 8a 9c b5 ?? ?? ?? ?? 88 5d ?? 8b 9c 85 ?? ?? ?? ?? 89 9c b5 ?? ?? ?? ?? 33 db 8a 5d ?? 89 9c 85 ?? ?? ?? ?? 8b 9c b5 ?? ?? ?? ?? 03 9c 85 ?? ?? ?? ?? 81 e3 ff 00 00 00 8a 9c 9d ?? ?? ?? ?? 30 19 41 4a 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

