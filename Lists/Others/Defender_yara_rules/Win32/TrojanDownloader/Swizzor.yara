rule TrojanDownloader_Win32_Swizzor_2147566898_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor"
        threat_id = "2147566898"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "98047B0354E6472E21E7E658C581EAA5" ascii //weight: 2
        $x_2_2 = "8F569C59BBD4B05BAFD3963A3A0B22" ascii //weight: 2
        $x_2_3 = "4D3A8DC3F9C4F29EE0DB" ascii //weight: 2
        $x_2_4 = "KRSystem v1.0" ascii //weight: 2
        $x_1_5 = "AIEN " ascii //weight: 1
        $x_1_6 = "UrlMkSetSessionOption" ascii //weight: 1
        $x_2_7 = {68 74 74 70 3a 2f 2f 75 70 64 2e [0-16] 2e 63 6f 6d 2f 75 70 64 2f 63 68 65 63 6b}  //weight: 2, accuracy: Low
        $x_2_8 = {c1 e0 10 03 f0 81 f6 b3 3a 29 f0}  //weight: 2, accuracy: High
        $x_2_9 = "643EC0FBDB2DF584BAC9BCC695B98AA3D2E5DD8627D8A3D5" ascii //weight: 2
        $x_1_10 = "Download UBAgent" ascii //weight: 1
        $x_1_11 = "updbho.dll" ascii //weight: 1
        $x_1_12 = "CreateRemoteThread" ascii //weight: 1
        $x_1_13 = "ReadProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Swizzor_C_2147603383_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.gen!C"
        threat_id = "2147603383"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 00 00 [0-5] 0f 00 00 00 [0-32] b8 2e 00 00 00 [0-10] b9 0f 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4a 3c 01 ?? 8b 51 7c 8b ?? 78}  //weight: 1, accuracy: Low
        $x_1_3 = {7f 02 00 00 0f 8d [0-16] 81 ?? 7f 00 00 00 0f 8f 02 00}  //weight: 1, accuracy: Low
        $x_10_4 = {85 c0 0f 84 [0-26] c1 ?? 05 c1 2d ?? ?? ?? 00 1b 0b ?? ?? ?? ?? 00 (83|81 e8 41 00) 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Swizzor_J_2147603634_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.J"
        threat_id = "2147603634"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e8 00 00 00 00 b8 6f 83 00 00 5b 03 c3 ff e0}  //weight: 10, accuracy: High
        $x_10_2 = {8a 17 32 14 18 88 17 40 83 f8 ?? 7c 02}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Swizzor_E_2147610923_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.gen!E"
        threat_id = "2147610923"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 d8 8b c6 d1 e8 03 44 24 ?? 8b 0d ?? ?? ?? ?? 99 f7 3d ?? ?? ?? ?? 83 c6 02 83 c4 08 83 c7 01 32 1c 0a 3b 74 24 ?? 88 5f ff 7c ba}  //weight: 1, accuracy: Low
        $x_1_2 = {3b c6 75 09 b8 a1 7a 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Swizzor_F_2147612729_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.gen!F"
        threat_id = "2147612729"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 28 33 ce 0f ac fe 08 81 e1 ff 00 00 00 33 34 cd ?? ?? ?? ?? c1 ef 08 33 3c cd ?? ?? ?? ?? 83 c0 01 3b c2 7c d8}  //weight: 1, accuracy: Low
        $x_1_2 = {c0 e1 04 99 f7 7e 04 8b 06 02 cb 8b 5f f4 8d 73 01 32 0c 02 8b 47 f8 88 4c 24 ?? b9 01 00 00 00 2b 4f fc 2b c6 0b c1 7d 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Swizzor_G_2147614106_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.gen!G"
        threat_id = "2147614106"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fb 5a 7e d9 39 7d fc 75 07 c7 45 fc 6e e1 00 00 81 75 fc 1c f5 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 39 8b d6 81 e2 ff 00 00 00 33 d7 c1 ee 08 33 34 95 ?? ?? ?? ?? 83 e8 01 83 c1 01 85 c0 75 df}  //weight: 1, accuracy: Low
        $x_2_3 = {f7 79 04 8b 01 b9 01 00 00 00 2b 4e fc 32 1c 02 8b 56 f4 8b 46 f8 8d 6a 01 2b c5 0b c1 89 54 24 ?? 7d 12}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Swizzor_H_2147618893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.gen!H"
        threat_id = "2147618893"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 73 01 32 0c 02 8b 47 f8 88 4c 24 17 b9 01 00 00 00 2b 4f fc 2b c6 0b c1 7d 0e}  //weight: 1, accuracy: High
        $x_1_2 = {0f be 04 19 33 c6 0f ac fe 08 25 ff 00 00 00 33 34 c5 ?? ?? ?? ?? c1 ef 08 33 3c c5 ?? ?? ?? ?? 41 3b ca 7c db}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Swizzor_I_2147627346_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.gen!I"
        threat_id = "2147627346"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 74 24 0c 83 19 89 12 6a 00 8d 54 24 14 52 68 20 04 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 02 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 52 78 6a 00 ?? ?? ?? ?? ?? ?? ff d2 ?? ?? ?? ?? ?? ?? 8b 51 70 68 00 22 00 00 50 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Swizzor_J_2147627479_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.gen!J"
        threat_id = "2147627479"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c5 99 2b c2 d1 f8 03 c7 99 f7 7e 04 8b 06 c0 e1 04 02 cb 32 0c 02}  //weight: 1, accuracy: High
        $x_1_2 = {35 00 00 00 d8 89 0c fd ?? ?? ?? ?? 89 04 fd ?? ?? ?? ?? 47 81 ff ff 00 00 00 0f 8e 1d ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 8e a4 00 00 00 53 68 58 1b 00 00 51 32 db ff 15 ?? ?? ?? ?? 85 c0 75 33 39 46 38 74 21 8b 7c 24 10 8b 96 a8 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Swizzor_K_2147628190_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.gen!K"
        threat_id = "2147628190"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 99 f7 3d ?? ?? ?? ?? a1 ?? ?? ?? ?? 83 45 fc 02 32 0c 02 8b 45 fc 88 0e 46 3b 45 f8 7c b3}  //weight: 1, accuracy: Low
        $x_1_2 = {83 fb 5a 7e d9 39 75 d4 75 07 c7 45 d4 19 2e 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Swizzor_L_2147628494_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.gen!L"
        threat_id = "2147628494"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "get_file.php?file=" ascii //weight: 2
        $x_2_2 = "C4DL Media" ascii //weight: 2
        $x_2_3 = "&affid_tr=" ascii //weight: 2
        $x_2_4 = "\\minime.exe" ascii //weight: 2
        $x_1_5 = "\\HtmlControl.dll" ascii //weight: 1
        $x_1_6 = "\\htmlcontrol3" ascii //weight: 1
        $x_1_7 = "install_complete.php?AppProgram=" ascii //weight: 1
        $x_1_8 = ".dll::PayFunc(" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Swizzor_AB_2147643470_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.AB"
        threat_id = "2147643470"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c:\\windows\\KB978978.log" ascii //weight: 1
        $x_1_2 = "C:\\WINDOWS\\system32\\drivers\\etc\\service1.ini" ascii //weight: 1
        $x_1_3 = {70 72 6f 63 65 73 73 31 00 70 72 6f 63 65 73 73 32}  //weight: 1, accuracy: High
        $x_1_4 = {61 62 6f 75 74 3a 62 6c 61 6e 6b 00 68 74 74 70 3a 2f 2f 73 74 61 74 2e 77 61 6d 6d 65 2e 63 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Swizzor_AB_2147643470_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Swizzor.AB"
        threat_id = "2147643470"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Swizzor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\WINDOWS\\system32\\drivers\\etc\\service1.ini" ascii //weight: 1
        $x_1_2 = "c:\\windows\\KB978978.log" ascii //weight: 1
        $x_1_3 = "e:\\JinZQ\\" ascii //weight: 1
        $x_1_4 = {70 72 6f 63 65 73 73 31 00 70 72 6f 63 65 73 73 32}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

