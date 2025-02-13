rule Trojan_Win32_Patched_AF_2147596329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Patched.AF"
        threat_id = "2147596329"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Patched"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "shell32" ascii //weight: 1
        $x_1_2 = "ShellExecute" ascii //weight: 1
        $x_5_3 = {5a 52 52 bb ?? ?? ?? ?? ff d3 5b 53 83 c3 0c 53 50 b9 ?? ?? ?? ?? ff d1 5a 6a 01 6a 00 6a 00 8b ca 83 c1 1a 51 6a 00 6a 00 ff d0 b8 ?? ?? ?? ?? ff e0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Patched_R_2147630895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Patched.R"
        threat_id = "2147630895"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Patched"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 64 6c 6c 00 53 66 63 47 65 74 46 69 6c 65 73}  //weight: 10, accuracy: High
        $x_10_2 = {83 7d 0c 00 75 [0-32] 83 3d ?? ?? 00 10 00 74 1e eb 04 89 ?? 4e df ff 35 ?? ?? 00 10 ff 35 ?? ?? 00 10 68 ?? ?? 00 10 e8 ?? ?? ff ff ff d0 [0-32] eb 07 6a 00 e8 ?? 00 00 00 83 3d ?? ?? 00 10 00 75 f0}  //weight: 10, accuracy: Low
        $x_10_3 = {81 c2 34 06 00 00 (ff|8b 1a) 33 c3 83 e1 01 33 04 8d ?? ?? 00 10}  //weight: 10, accuracy: Low
        $x_1_4 = {68 04 01 00 00 53 ff 35 ?? ?? 00 10 68 ?? ?? 00 10 e8 ?? ?? ff ff ff d0 8d 1d ?? ?? 00 10 eb 0b}  //weight: 1, accuracy: Low
        $x_1_5 = {ff d0 8d 1d ?? ?? 00 10 6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 68 00 00 00 80 53 ff 35 ?? ?? 00 10 68 ?? ?? 00 10 e8 ?? ?? ff ff ff d0}  //weight: 1, accuracy: Low
        $x_1_6 = {81 e2 ff ff 00 00 [0-4] 03 d3 [0-8] 8a 02 35 00 ?? 00 00 3d cc ?? 00 00 75 02 33 d0 [0-5] ec 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Patched_T_2147637446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Patched.T"
        threat_id = "2147637446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Patched"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 65 6d 70 c7 45 ?? 6f 72 61 72}  //weight: 1, accuracy: Low
        $x_1_2 = {eb 02 aa aa e9 80 03 00 00 8b 4c 24 04 56 8b 74 24 0c 8a 01}  //weight: 1, accuracy: High
        $x_1_3 = {ff 55 ec 5f 5e 5b c9 c3 83 7c 24 08 01 75 07 60}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Patched_V_2147642934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Patched.V"
        threat_id = "2147642934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Patched"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 e8 34 89 85 ?? ?? ?? ?? 61 ff 34 24 60 e8 00 00 00 00 5d 81 ed ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 89 44 24 24 61 5d 83 7c 24 0c 01 75 26 60 e8 00 00 00 00 5d 81 ed ?? ?? ?? ?? 8d b5 ?? ?? ?? ?? 56 8b bd ?? ?? ?? ?? ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {55 60 e8 00 00 00 00 90 90 8b f6 5d 81 ed ?? ?? ?? ?? 60 e8 00 00 00 00 58 25 00 f0 ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {a4 cf 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 6d 73 63 74 66 69 6d 65 2e 69 65 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Patched_W_2147642948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Patched.W"
        threat_id = "2147642948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Patched"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a c1 8a d1 f6 e9 80 f2 01 80 e2 07 32 c2 8a 14 31 32 d0 88 14 31 41 3b cf 72 e5}  //weight: 1, accuracy: High
        $x_1_2 = {68 89 fd 12 a4 56 89 75 ec e8 ?? ?? ?? ?? 68 19 d0 d6 02 56 8b f8 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Patched_AE_2147643278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Patched.AE"
        threat_id = "2147643278"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Patched"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 00 00 10 e0 8d 0f 51 ff 10}  //weight: 1, accuracy: High
        $x_1_2 = {68 3f 00 5c 00 68 5c 00 3f 00 66 89 47 1c 89 67 20 be 0d 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Patched_AH_2147643289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Patched.AH"
        threat_id = "2147643289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Patched"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "master.dyngate.com" ascii //weight: 1
        $x_1_2 = "SecurityPasswordAES" wide //weight: 1
        $x_1_3 = "Goldstager5_Logfile.log" wide //weight: 1
        $x_1_4 = "HKEY_LOCAL_MACHINE\\Software\\Goldstager\\Version5" wide //weight: 1
        $x_1_5 = "Coinstager5_Logfile.log" wide //weight: 1
        $x_1_6 = "HKEY_LOCAL_MACHINE\\Software\\Coinstager\\Version5" wide //weight: 1
        $x_1_7 = "SKTTeleCom5_Logfile.log" wide //weight: 1
        $x_1_8 = "HKEY_LOCAL_MACHINE\\Software\\SKTTeleCom\\Version5" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_Patched_KA_2147912715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Patched.KA"
        threat_id = "2147912715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Patched"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a1 58 ba 08 10 c7 44 24 0c 04 00 00 00 c7 44 24 08 00 10 00 00 89 44 24 04 c7 04 24 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 10 89 c6 c7 44 24 4c 00 00 00 00 c7 44 24 10 00 00 00 00 8d 44 24 4c 89 44 24 0c 89 6c 24 08 89 74 24 04 89 1c 24 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {89 44 24 04 89 3c 24 ff 15 ?? ?? ?? ?? 83 ec 08 89 c7 85 c0 0f 84 e8 00 00 00 0f be 03 01 c3 8d 43 01 89 04 24 ff d5 83 ec 04 85 c0}  //weight: 1, accuracy: Low
        $x_1_3 = {80 3c 11 00 75 e1 66 c7 04 46 00 00 89 74 24 40 8b 44 24 2c 89 44 24 3c c6 44 24 44 01 8d 44 24 3c 89 04 24 ff d3 83 c4 5c 5b 5e 5f 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

