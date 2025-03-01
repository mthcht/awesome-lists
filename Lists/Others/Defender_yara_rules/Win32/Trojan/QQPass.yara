rule Trojan_Win32_QQPass_GB_2147709647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQPass.GB!bit"
        threat_id = "2147709647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQPass"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\Program Files\\Exporer.exe" ascii //weight: 2
        $x_1_2 = "&qqpassword=" ascii //weight: 1
        $x_1_3 = "?qqnumber=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QQPass_GE_2147710265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQPass.GE!bit"
        threat_id = "2147710265"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQPass"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "BlackMoon RunTime Error:" ascii //weight: 10
        $x_10_2 = {3f 41 63 74 69 6f 6e 3d [0-8] 26 55 73 65 72 3d}  //weight: 10, accuracy: Low
        $x_3_3 = {53 65 74 50 72 6f 78 79 00 53 65 74 50 72 6f 78 79 43 72 65 64 65 6e 74 69 61 6c 73 00 4f 70 65 6e 00 4f 70 74 69 6f 6e}  //weight: 3, accuracy: High
        $x_3_4 = {54 41 53 4c 6f 67 69 6e 2e 65 78 65 00 63 6c 69 65 6e 74 2e 65 78 65 00 75 69 5c 44 4e 46 43 6c 69 65 6e 74}  //weight: 3, accuracy: High
        $x_1_5 = {cc da d1 b6 d3 ce cf b7 c6 bd cc a8}  //weight: 1, accuracy: High
        $x_1_6 = {44 4e 46 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = "Bank of America log-in" ascii //weight: 1
        $x_1_8 = "FSAV.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_QQPass_GF_2147712011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQPass.GF!bit"
        threat_id = "2147712011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQPass"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 73 68 65 6c 6c 5c 4f 70 65 6e 48 6f 6d 65 50 61 67 65 5c 43 6f 6d 6d 61 6e 64 7c 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 22 20 68 74 74 70 3a 2f 2f 77 77 77 2e 32 33 34 35 2e 63 6f 6d 2f [0-16] 0d 0a ?? 7c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c 53 74 61 72 74 20 50 61 67 65 7c 68 74 74 70 3a 2f 2f 77 77 77 2e 32 33 34 35 2e 63 6f 6d 2f [0-16] 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = {77 77 77 2e 39 69 66 7a 2e 6f 72 67 2f [0-16] 71 71 64 61 6f 68 61 6f 2f 3f 6e 61 6d 65 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QQPass_G_2147740747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQPass.G!MTB"
        threat_id = "2147740747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*YiYuYanWoChiLe*.htm" ascii //weight: 1
        $x_1_2 = "Sysqamqqvaqqd.exe" ascii //weight: 1
        $x_1_3 = "qpath.ini" ascii //weight: 1
        $x_1_4 = "QQProtect.exe" ascii //weight: 1
        $x_1_5 = "QQApp.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QQPass_DA_2147779246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQPass.DA!MTB"
        threat_id = "2147779246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 55 e2 8b 45 c8 80 ea 03 32 55 e3 88 14 30 3b 5e f8 0f 8f}  //weight: 1, accuracy: High
        $x_1_2 = "KLJEWERHsdwqeh23211!@asdqSADwe" ascii //weight: 1
        $x_1_3 = "BRESUZCDY.jpg" ascii //weight: 1
        $x_1_4 = "wahaha" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QQPass_GZZ_2147905920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQPass.GZZ!MTB"
        threat_id = "2147905920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {1e ec 16 41 00 00 1e a4 1a 41 00 00 1e 0c ee 42 00 00 1e 14 ed 42 00 00 1e 30 1b 41 00 00 1e 40 1b 41 00 00 1e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QQPass_GZY_2147906303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQPass.GZY!MTB"
        threat_id = "2147906303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5d 81 ed 10 00 00 00 81 ed ?? ?? ?? ?? e9 ?? ?? ?? ?? 03 df d1 6b b8 28 f6 a3 ?? ?? ?? ?? c0 4c 00 00 00 b9 a1 05 00 00 ba ?? ?? ?? ?? 30 10}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_QQPass_BSA_2147926887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/QQPass.BSA!MTB"
        threat_id = "2147926887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "QQPass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {85 c0 75 08 6a 1c e8 ?? ?? ?? ?? 59 e8 ?? ?? ?? ?? 85 c0 75 08 6a 10 e8 ?? ?? ?? ?? 59 33 f6 89 75 ?? e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? e8}  //weight: 10, accuracy: Low
        $x_1_2 = "d09f2340818511d396f6aaf844c7e325" ascii //weight: 1
        $x_1_3 = "707ca37322474f6ca841f0e224f4b620" ascii //weight: 1
        $x_1_4 = "A512548E76954B6E92C21055517615B0" ascii //weight: 1
        $x_1_5 = "xui.ptlogin2.qq.com/cgi-bin/qlogin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

