rule Trojan_Win32_SuspClickFix_A_2147941552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.A"
        threat_id = "2147941552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_3_2 = "http" wide //weight: 3
        $x_3_3 = " -o " wide //weight: 3
        $x_1_4 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_5 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-32] 2e 00 62 00 61 00 74 00}  //weight: 1, accuracy: Low
        $x_1_6 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 [0-32] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-32] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_8 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 [0-32] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_9 = ".aliyuncs.com/" wide //weight: 1
        $x_1_10 = ".myqcloud.com/" wide //weight: 1
        $x_1_11 = {5c 00 4d 00 75 00 73 00 69 00 63 00 5c 00 [0-48] 2e 00 6d 00 73 00 69 00}  //weight: 1, accuracy: Low
        $x_1_12 = {5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 [0-48] 2e 00 70 00 64 00 66 00}  //weight: 1, accuracy: Low
        $x_4_13 = {20 00 2d 00 4c 00 20 00 25 00 ?? ?? ?? ?? 25 00 ?? ?? ?? ?? 25 00 ?? ?? ?? ?? 25 00 ?? ?? ?? ?? 25 00 ?? ?? ?? ?? 25 00}  //weight: 4, accuracy: Low
        $x_1_14 = {20 00 2d 00 6f 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 [0-48] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
        $x_1_15 = {20 00 2d 00 6f 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 [0-48] 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
        $x_1_16 = {20 00 2d 00 6f 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 [0-48] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
        $x_1_17 = {20 00 2d 00 6f 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 [0-48] 2e 00 6a 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_B_2147941553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.B"
        threat_id = "2147941553"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "http" wide //weight: 1
        $n_10_4 = "--url http" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (2 of ($x*))
}

rule Trojan_Win32_SuspClickFix_C_2147941554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.C"
        threat_id = "2147941554"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {5c 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = "iwr " wide //weight: 5
        $x_1_3 = "iex $" wide //weight: 1
        $x_1_4 = "| iex" wide //weight: 1
        $x_1_5 = "|iex" wide //weight: 1
        $x_1_6 = ";iex " wide //weight: 1
        $x_1_7 = "iex(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_D_2147941555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.D"
        threat_id = "2147941555"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 10, accuracy: High
        $x_5_2 = "http" wide //weight: 5
        $x_1_3 = "| powershell" wide //weight: 1
        $x_1_4 = "|powershell" wide //weight: 1
        $x_1_5 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-32] 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_E_2147941628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.E"
        threat_id = "2147941628"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 20 00 63 00 61 00 6c 00 6c 00 20 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 20 00 [0-64] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_F_2147942715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.F"
        threat_id = "2147942715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 00 74 00 61 00 72 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = {20 00 2d 00 78 00 66 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00 [0-32] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = {20 00 2d 00 43 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-32] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 52 00 6f 00 61 00 6d 00 69 00 6e 00 67 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {20 00 2d 00 78 00 66 00 20 00 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-32] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_5 = " -C C:\\ProgramData\\" wide //weight: 1
        $x_1_6 = {20 00 2d 00 78 00 66 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c 00 [0-48] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_7 = " -C C:\\Users\\Public\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_H_2147943617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.H"
        threat_id = "2147943617"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " cmd.exe /c cmd.exe /c " wide //weight: 1
        $x_1_3 = "POST" wide //weight: 1
        $x_1_4 = "http" wide //weight: 1
        $x_1_5 = ".php" wide //weight: 1
        $x_1_6 = " -o " wide //weight: 1
        $x_1_7 = "&& start " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_I_2147947479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.I"
        threat_id = "2147947479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 66 00 74 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $n_10_2 = "57859b6e-ec4b-479a-a155-a5e9248683d6" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_J_2147947870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.J"
        threat_id = "2147947870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-16] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_K_2147947871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.K"
        threat_id = "2147947871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-16] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_Q_2147962549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Q"
        threat_id = "2147962549"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 26 00 20 00 63 00 75 00 72 00 6c 00 [0-32] 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {20 00 3e 00 20 00 [0-32] 2e 00 74 00 61 00 72 00 20 00}  //weight: 1, accuracy: Low
        $x_1_3 = " & tar" wide //weight: 1
        $x_1_4 = " & start python" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_R_2147962996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.R"
        threat_id = "2147962996"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "nslookup" wide //weight: 5
        $x_1_2 = " | findstr ^Name:" wide //weight: 1
        $x_1_3 = " | findstr powershell" wide //weight: 1
        $x_1_4 = " | for /f" wide //weight: 1
        $x_1_5 = "tokens=" wide //weight: 1
        $x_1_6 = "delims=" wide //weight: 1
        $x_1_7 = " | cmd" wide //weight: 1
        $x_1_8 = " | C:\\Windows\\System32\\cmd.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_R2_2147963245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.R2"
        threat_id = "2147963245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 6e 00 73 00 6c 00 6f 00 6f 00 6b 00 75 00 70 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {6e 00 73 00 6c 00 6f 00 6f 00 6b 00 75 00 70 00 [0-8] 20 00 [0-64] 2e 00 [0-6] 2e 00 [0-6] 2e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_Q2_2147963694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Q2"
        threat_id = "2147963694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "=mshta&set " wide //weight: 1
        $x_1_3 = "&call !" wide //weight: 1
        $x_1_4 = "&ping " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_Q2_2147963694_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Q2"
        threat_id = "2147963694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "=msiexec" wide //weight: 1
        $x_1_3 = "&& call %" wide //weight: 1
        $x_1_4 = " http" wide //weight: 1
        $x_1_5 = " /i " wide //weight: 1
        $x_1_6 = " /q" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_Q2_2147963694_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Q2"
        threat_id = "2147963694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = " /c start /min " wide //weight: 1
        $x_3_3 = "curl " wide //weight: 3
        $x_1_4 = " do call %" wide //weight: 1
        $x_1_5 = " /v:on /c set " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_R3_2147964389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.R3"
        threat_id = "2147964389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "| powershell" wide //weight: 1
        $x_1_3 = "| cmd &&" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_T_2147964390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.T"
        threat_id = "2147964390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 [0-2] 5c 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_S2_2147964498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.S2"
        threat_id = "2147964498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 2f 00 63 00 20 00 6e 00 65 00 74 00 20 00 75 00 73 00 65 00 20 00 [0-2] 3a 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = " /persistent:no && " wide //weight: 1
        $x_1_3 = ".cmd" wide //weight: 1
        $x_1_4 = {20 00 26 00 20 00 6e 00 65 00 74 00 20 00 75 00 73 00 65 00 20 00 [0-2] 3a 00 20 00 2f 00 64 00 65 00 6c 00 65 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = ".ps1 & net" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_SuspClickFix_U_2147964735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.U"
        threat_id = "2147964735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 00 63 00 68 00 6f 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = ").content" wide //weight: 1
        $x_1_3 = "| for /f " wide //weight: 1
        $x_1_4 = " | %" wide //weight: 1
        $x_1_5 = ".exe') do %" wide //weight: 1
        $x_2_6 = {63 00 75 00 72 00 6c 00 20 00 [0-32] 68 00 74 00 74 00 70 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_V_2147965059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.V"
        threat_id = "2147965059"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "--headless" wide //weight: 1
        $x_1_3 = " /c start /min " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_T2_2147965158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.T2"
        threat_id = "2147965158"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 20 00 2f 00 73 00 20 00 [0-2] 5c 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 5c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_Q3_2147967020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Q3"
        threat_id = "2147967020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " && curl " wide //weight: 1
        $x_1_2 = " && tar -xf" wide //weight: 1
        $x_1_3 = " /c mkdir " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_Q3_2147967020_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Q3"
        threat_id = "2147967020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = {43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-48] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = ".pdf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_W_2147967257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.W"
        threat_id = "2147967257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = "|ssh " wide //weight: 2
        $x_2_3 = "|cmd" wide //weight: 2
        $x_1_4 = " -o StrictHostKeyChecking=no" wide //weight: 1
        $x_1_5 = {20 00 2d 00 6f 00 20 00 55 00 73 00 65 00 72 00 4b 00 6e 00 6f 00 77 00 6e 00 48 00 6f 00 73 00 74 00 73 00 46 00 69 00 6c 00 65 00 3d 00 4e 00 55 00 4c 00 [0-32] 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_W2_2147967258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.W2"
        threat_id = "2147967258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = "& echo " wide //weight: 1
        $x_1_3 = {20 00 7c 00 20 00 63 00 75 00 72 00 6c 00 20 00 2d 00 58 00 20 00 50 00 4f 00 53 00 54 00 20 00 2d 00 46 00 20 00 [0-16] 3d 00 40 00 2d 00 20 00 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_V2_2147967489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.V2"
        threat_id = "2147967489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = " --headless" wide //weight: 1
        $x_1_3 = "curl " wide //weight: 1
        $x_1_4 = "| cmd" wide //weight: 1
        $x_1_5 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-64] 2c 00 23 00}  //weight: 1, accuracy: Low
        $x_2_6 = {70 00 75 00 73 00 68 00 64 00 5c 00 5c 00 [0-64] 26 00 63 00 6d 00 64 00 3c 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_R4_2147967685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.R4"
        threat_id = "2147967685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = " do call %" wide //weight: 1
        $x_1_3 = "& exit" wide //weight: 1
        $x_1_4 = "&& echo " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_R5_2147967686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.R5"
        threat_id = "2147967686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = " do curl" wide //weight: 1
        $x_1_3 = "for /f " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_X_2147967687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.X"
        threat_id = "2147967687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_2_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-8] 20 00 5c 00 5c 00 [0-96] 2e 00 69 00 6e 00 2e 00 6e 00 65 00 74 00 5c 00}  //weight: 2, accuracy: Low
        $x_2_3 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-8] 20 00 5c 00 5c 00 [0-96] 2e 00 67 00 61 00 72 00 64 00 65 00 6e 00 5c 00}  //weight: 2, accuracy: Low
        $x_1_4 = ",#1" wide //weight: 1
        $x_1_5 = ".chk,#" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_X_2147967687_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.X"
        threat_id = "2147967687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_2_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-8] 20 00 5c 00 5c 00 [0-48] 2e 00 [0-16] 40 00 38 00 30 00 5c 00}  //weight: 2, accuracy: Low
        $x_1_3 = ".verify" wide //weight: 1
        $x_1_4 = ".google,#1" wide //weight: 1
        $x_1_5 = ".google,Verif" wide //weight: 1
        $x_1_6 = ".cloudflare,#1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_X_2147967687_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.X"
        threat_id = "2147967687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_2_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-8] 20 00 5c 00 5c 00 [0-96] 2e 00 [0-16] 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2d 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d 00}  //weight: 2, accuracy: Low
        $x_1_3 = ".verify" wide //weight: 1
        $x_1_4 = ".google,#1" wide //weight: 1
        $x_1_5 = ".google,Verif" wide //weight: 1
        $x_1_6 = ".cloudflare,#1" wide //weight: 1
        $x_1_7 = "fa542c,#1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_Q4_2147967781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Q4"
        threat_id = "2147967781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 2d 00 6f 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 [0-48] 5c 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 5c 00 4c 00 6f 00 63 00 61 00 6c 00 5c 00 54 00 65 00 6d 00 70 00 5c 00 [0-16] 2e 00 70 00 73 00 31 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_Q5_2147968172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Q5"
        threat_id = "2147968172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 00 43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 73 00 65 00 74 00 20 00}  //weight: 1, accuracy: High
        $x_1_2 = "& call set " wide //weight: 1
        $x_1_3 = "& set " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SuspClickFix_X_2147968173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.X!gen"
        threat_id = "2147968173"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-8] 20 00 5c 00 5c 00 [0-96] 2e 00 [0-16] 5c 00}  //weight: 3, accuracy: Low
        $x_1_3 = ",#" wide //weight: 1
        $x_1_4 = ",run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_Z_2147968174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.Z"
        threat_id = "2147968174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 75 00 73 00 68 00 64 00 20 00 5c 00 5c 00 [0-96] 5c 00}  //weight: 1, accuracy: Low
        $x_1_2 = {26 00 26 00 [0-32] 6f 00 64 00 62 00 63 00 63 00 6f 00 6e 00 66 00 20 00 [0-16] 66 00}  //weight: 1, accuracy: Low
        $x_2_3 = "conhost --headless odbcconf /f \\\\" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SuspClickFix_AA_2147968175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspClickFix.AA"
        threat_id = "2147968175"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspClickFix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5c 00 73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = " /create" wide //weight: 1
        $x_1_3 = " /sc minute" wide //weight: 1
        $x_1_4 = " /mo 1" wide //weight: 1
        $x_1_5 = " /tn " wide //weight: 1
        $x_2_6 = {20 00 2f 00 74 00 72 00 20 00 [0-64] 69 00 65 00 78 00 28 00 69 00 72 00 6d 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

