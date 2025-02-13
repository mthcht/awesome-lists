rule Trojan_Win32_Dishigy_A_2147640674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dishigy.A"
        threat_id = "2147640674"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dishigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 b8 24 00 e8 ?? ?? ?? ?? 8b 55 ec}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 e7 03 00 00 e8 ?? ?? ?? ?? 8d 55 d8}  //weight: 1, accuracy: Low
        $x_1_3 = {c7 80 c8 01 00 00 db 05 00 00 8b 45 f8 83 c0 34 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? b8 75 00 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dishigy_B_2147642017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dishigy.B"
        threat_id = "2147642017"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dishigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "27. 77. .7. 8.1." ascii //weight: 1
        $x_1_2 = "\\keys.ini" ascii //weight: 1
        $x_1_3 = "\\system32\\drivers\\" ascii //weight: 1
        $x_1_4 = "Mozilla/5.0 (Windows" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dishigy_D_2147653386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dishigy.D"
        threat_id = "2147653386"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dishigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "googlebot" ascii //weight: 1
        $x_1_2 = "@somewhere" ascii //weight: 1
        $x_1_3 = {26 73 79 6e 61 66 70 63 00 [0-48] 24 73 79 6e 61 69 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dishigy_E_2147656274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dishigy.E"
        threat_id = "2147656274"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dishigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "googlebot" ascii //weight: 1
        $x_1_2 = "@somewhere" ascii //weight: 1
        $x_1_3 = {26 73 79 6e 61 66 70 63 00 [0-48] 24 73 79 6e 61 69 70 00}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 1, accuracy: High
        $x_1_5 = "\\system32\\drivers\\svchost.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dishigy_A_2147656348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dishigy.gen!A"
        threat_id = "2147656348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dishigy"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 40 1c c7 80 c8 01 00 00 db 05 00 00 8b 45 f8 83 c0 34}  //weight: 1, accuracy: High
        $x_1_2 = {69 45 f8 e7 03 00 00 50 e8 ?? ?? ?? ?? e9 ?? ?? ?? ?? b2 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dishigy_H_2147681906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dishigy.H"
        threat_id = "2147681906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dishigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 1, accuracy: High
        $x_1_2 = "tkekqeY" ascii //weight: 1
        $x_1_3 = "login=[1000]&pass=[1000]&password=[50]&log=[50]&passwrd=[50]&user" ascii //weight: 1
        $x_1_4 = "systemskey.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dishigy_J_2147682954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dishigy.J"
        threat_id = "2147682954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dishigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 c3 01 0a 00 00 8b ?? e4 83 ?? ?? 76 ?? e8 ?? ?? ?? ?? 69 ?? 32 f4 01 00 8d ?? ?? ?? ?? ?? ?? 8d 04}  //weight: 1, accuracy: Low
        $x_1_2 = "<qrcj=/oiqX" ascii //weight: 1
        $x_1_3 = "login=[1000]&pass=[1000]&password=[50]&log=[50]&passwrd=[50]&user=[50]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dishigy_K_2147706358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dishigy.K"
        threat_id = "2147706358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dishigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 41 01 80 39 e9 74 0c 80 39 eb 75 0c 0f be c0 41 41 eb 03 83 c1 05 01 c1}  //weight: 1, accuracy: High
        $x_1_2 = {bf 01 00 00 00 8b 45 ?? 03 06 05 05 33 db 8a 5c 38 ff 0f b6 5c 38 ff 0f b7 5c 78 fe 33 5d ?? 3b 5d ?? 7f 0b 81 c3 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "quinas Virtuais." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dishigy_K_2147706358_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dishigy.K"
        threat_id = "2147706358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dishigy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 68 58 4d 56 b9 0a 00 00 00 66 ba 58 56 ed}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 5c 78 fe 33 5d e0 3b 5d e4 7f 0b 81 c3 ff 00 00 00 2b 5d e4 eb 03 2b 5d e4 8d 45 c8 8b d3 e8}  //weight: 1, accuracy: High
        $x_1_3 = {74 17 8d 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 f4 8b c3 e8 ?? ?? ?? ?? 8d 55 f0 a1 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f0 50 8d 55 ec b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 ec 5a e8 ?? ?? ?? ?? 84 c0 74 17 8d 55 e8 b8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

