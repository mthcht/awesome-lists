rule Trojan_Win32_Dursg_B_2147616229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dursg.B"
        threat_id = "2147616229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dursg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {74 4f 56 57 e8 ?? ?? 00 00 8b f8 6a 23 57 e8 ?? ?? 00 00 8b e8 8b f5 2b f7 d1 fe}  //weight: 2, accuracy: Low
        $x_2_2 = {74 6d 53 55 56 57 e8 ?? ?? 00 00 8b f0 6a 23 56 e8 ?? ?? 00 00 8b e8 8b dd 2b de}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 04 24 83 78 0c 02 53 50 0f 94 c3 e8 ?? ?? ?? ?? 80 fb 01 5b b8 ?? ?? ?? ?? 74 05 b8}  //weight: 2, accuracy: Low
        $x_1_4 = {75 72 73 3d 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 63 70 3d 00}  //weight: 1, accuracy: High
        $x_1_6 = {63 6d 70 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dursg_A_2147616230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dursg.A"
        threat_id = "2147616230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dursg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 00 79 00 61 00 6e 00 64 00 73 00 65 00 61 00 72 00 63 00 68 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 00 6e 00 69 00 68 00 65 00 72 00 61 00 64 00 6f 00 6d 00 65 00 6e 00 2e 00 63 00 6f 00 6d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "9DCD-7282A2D07862" wide //weight: 1
        $x_10_4 = "Global\\Mila_term" ascii //weight: 10
        $x_10_5 = "%S&ver=%S&uid=%S" ascii //weight: 10
        $x_10_6 = "\\Microsoft\\VSU" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dursg_C_2147630362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dursg.C"
        threat_id = "2147630362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dursg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "request.php?aid=%s" wide //weight: 1
        $x_1_2 = {51 50 6a 00 ff d2 14 00 8b 44 24 04 8b 90 ?? ?? ?? ?? 6a 00 6a 00 8d 88}  //weight: 1, accuracy: Low
        $x_1_3 = {3c 01 74 42 6a 00 68 80 00 00 00 6a 03 6a 00 6a 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Dursg_D_2147631329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dursg.D"
        threat_id = "2147631329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dursg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://%s/se.php?pop=1&aid=%s&sid=%s&key=%s" wide //weight: 1
        $x_1_2 = "request.php?aid=%s" wide //weight: 1
        $x_1_3 = {50 68 19 00 02 00 6a 00 68 2c 5a 41 00 68 01 00 00 80 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 68 00 00 00 80 56 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dursg_E_2147632118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dursg.E"
        threat_id = "2147632118"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dursg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 04 24 83 78 0c 02 53 50 0f 94 c3 e8 ?? ?? ?? ?? 80 fb 01 5b b8 ?? ?? ?? ?? 74 05 b8}  //weight: 2, accuracy: Low
        $x_1_2 = "se.php?pop=1&aid=%s" wide //weight: 1
        $x_1_3 = "request.php?aid=%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dursg_2147646354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dursg"
        threat_id = "2147646354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dursg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d0 89 45 e0 8b 45 e0 89 45 9c 50 8b 45 9c 89 04 24 a1 ?? ?? ?? ?? ff d0 89 45 e4 8b 45 e4 89 45 a0 c7 45 a4 00 00 00 00 8b 45 a4 3d 20 a1 07 00 0f 8d ?? ?? 00 00 50 c7 04 24 1c 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {89 85 64 ff ff ff 8b 85 64 ff ff ff 8b 40 02 83 c0 ca 89 85 68 ff ff ff 8b 85 5c ff ff ff f7 d8 03 85 68 ff ff ff 89 85 6c ff ff ff 50 8b 85 6c ff ff ff 89 04 24 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dursg_I_2147646653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dursg.I"
        threat_id = "2147646653"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dursg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pop=1&aid=%s&sid=%s&key=%s" wide //weight: 1
        $x_1_2 = "SERPv2" wide //weight: 1
        $x_1_3 = "%s\\lsass.exe" wide //weight: 1
        $x_1_4 = "KillSelf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Dursg_J_2147646854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dursg.J"
        threat_id = "2147646854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dursg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s?aid=%s&ver=%s&uid=%s&url=%s" wide //weight: 1
        $x_1_2 = "%stimer.xul" wide //weight: 1
        $x_1_3 = "/request.php" wide //weight: 1
        $x_1_4 = {67 00 6f 00 6f 00 67 00 6c 00 65 00 00 00 00 00 73 00 65 00 61 00 72 00 63 00 68 00 00 00 00 00 79 00 61 00 68 00 6f 00 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Dursg_K_2147656178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dursg.K"
        threat_id = "2147656178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dursg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<value id=\"download_URL\" null=\"yes\"/>" ascii //weight: 1
        $x_1_2 = "_tk.old" ascii //weight: 1
        $x_1_3 = "\" rk auto" ascii //weight: 1
        $x_1_4 = "Chrome_updater" ascii //weight: 1
        $x_1_5 = "ScriptUpdate=" ascii //weight: 1
        $x_1_6 = "TTibiaMainThread" ascii //weight: 1
        $x_1_7 = "download_exec_file" ascii //weight: 1
        $x_1_8 = "getfile=1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

