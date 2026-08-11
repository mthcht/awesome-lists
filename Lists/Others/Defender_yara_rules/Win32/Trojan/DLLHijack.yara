rule Trojan_Win32_DLLHijack_DA_2147901326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.DA!MTB"
        threat_id = "2147901326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 84 14 ?? ?? ?? ?? 33 d9 09 94 04 ?? ?? ?? ?? 13 f9 33 94 44 ?? ?? ?? ?? 0f be 0c 14 0b 54 95 ?? 0f c9 36 66 8b 84 82 ?? ?? ?? ?? 8d ac 4d ?? ?? ?? ?? 2b c9 81 d9 ?? ?? ?? ?? 66 89 44 25}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_DF_2147939451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.DF!MTB"
        threat_id = "2147939451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 34 0f 02 de 8a 14 1f 88 14 0f 88 34 1f 02 d6 0f b6 d2 8a 14 17 8a 0c 06 32 ca 5a 88 0c 02}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_DG_2147940536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.DG!MTB"
        threat_id = "2147940536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GUP.EXE LIBCURL.DLL PROXY - PAYLOAD THREAD" ascii //weight: 1
        $x_1_2 = "DLL_PROCESS_ATTACH (GUP.exe + shadowpipe.network:8443)" ascii //weight: 1
        $x_1_3 = "DLL-Sideloading" ascii //weight: 1
        $x_1_4 = "REMOTE INJECTION" ascii //weight: 1
        $x_1_5 = "SHELLCODE DOWNLOAD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_RPA_2147944575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.RPA!MTB"
        threat_id = "2147944575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 ec 33 c6 45 ed 38 c6 45 ee 2e c6 45 ef 31 c6 45 f0 38 c6 45 f1 31 c6 45 f2 2e c6 45 f3 34 c6 45 f4 32 c6 45 f5 2e c6 45 f6 31 c6 45 f7 32 c6 45 f8 37 c6 45 f9 00 c6 85 28 fc ff ff 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_DJ_2147962003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.DJ!MTB"
        threat_id = "2147962003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 45 e4 6c c6 45 e5 6f c6 45 e6 61 c6 45 e7 64 c6 45 e8 65 c6 45 e9 72 c6 45 ea 2e c6 45 eb 64 c6 45 ec 61 c6 45 ed 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_DP_2147968703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.DP!MTB"
        threat_id = "2147968703"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 1e 32 ca 88 0b 8b ca c1 e2 10 c1 e9 10 03 d1 6b d2 77 83 c2 13 43 4f 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_CAP_2147973630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.CAP!MTB"
        threat_id = "2147973630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 c5 83 e5 ?? 0f b6 4c 2e ?? 30 4c 06 ?? 8d 48 ?? 83 e1 ?? 0f b6 4c 0e ?? 30 4c 06 ?? 83 c0 02 39 c3 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_CAQ_2147973631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.CAQ!MTB"
        threat_id = "2147973631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 c0 01 c7 89 d8 f7 e1 d1 ea 83 e2 ?? 8d 04 52 f7 d8 0f b6 04 06 01 c7 43 0f b6 45 00 45 46 84 c0 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_PS_2147973660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.PS!MTB"
        threat_id = "2147973660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {34 b3 88 84 0c ?? ?? 00 00 41 83 f9 0b 72 eb 8d 84 24 ?? ?? 00 00 c6 84 24 ?? ?? 00 00 00 50 6a 01 6a 00 ff 15}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_GXN_2147973945_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.GXN!MTB"
        threat_id = "2147973945"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6d 0a 63 f8 14 73 00 01 3e 06 12 13 60 82 50 ?? 76 47 4c 31 98 ?? ?? ?? ?? 2d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_GPKH_2147974209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.GPKH!MTB"
        threat_id = "2147974209"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {48 83 ec 38 48 8d 54 24 20 48 8d 0d 60 93 03 00 e8 2b 74 00 00 48 8d 0d 74 7a 01 00 e8 df 4f 01 00 48 83 c4 38 c3}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_NYQ_2147975004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.NYQ!MTB"
        threat_id = "2147975004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 00 3a 00 5c 00 64 00 64 00 5c 00 76 00 63 00 74 00 6f 00 6f 00 6c 00 73 00 5c 00 76 00 63 00 37 00 6c 00 69 00 62 00 73 00 5c 00 73 00 68 00 69 00 70 00 5c 00 61 00 74 00 6c 00 6d 00 66 00 63 00 5c 00 [0-47] 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 [0-31] 2e 00 70 00 64 00 62 00}  //weight: 2, accuracy: Low
        $x_2_2 = {46 3a 5c 64 64 5c 76 63 74 6f 6f 6c 73 5c 76 63 37 6c 69 62 73 5c 73 68 69 70 5c 61 74 6c 6d 66 63 5c [0-47] 5c 52 65 6c 65 61 73 65 5c [0-31] 2e 70 64 62}  //weight: 2, accuracy: Low
        $x_2_3 = "\\Temp\\TAOAcceleratorEx64_ev.SYS" ascii //weight: 2
        $x_1_4 = "BB7BBB62FD9C76D5DDF37F17DDC3E7FF" ascii //weight: 1
        $x_1_5 = "38926a7FFFEF316D5CD0610EF31" ascii //weight: 1
        $x_1_6 = "cmd.exe /c start \"\" /B cmd /C %s" ascii //weight: 1
        $x_1_7 = "taskkill /f /im cmd.exe" ascii //weight: 1
        $x_1_8 = "6CC3288A937D15D79EF99F581CE2D91EA4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_DLLHijack_GXR_2147975011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.GXR!MTB"
        threat_id = "2147975011"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 02 99 b9 ?? ?? ?? ?? f7 f9 83 c2 ?? 8b 45 ?? 8b 48 ?? 8b 45 ?? 0f be 0c 01 33 ca 8b 55 ?? 8b 42 ?? 8b 55 ?? 88 0c 10 8b 45 ?? 83 c0 ?? 89 45}  //weight: 10, accuracy: Low
        $x_10_2 = {0f b6 00 99 b9 ?? ?? ?? ?? f7 f9 83 c2 ?? 8b 45 ?? 8b 40 ?? 8b 4d ?? 0f be 04 08 33 c2 8b 4d ?? 8b 49 ?? 8b 55 ?? 88 04 11 8b 45 ?? 40 89 45 ?? b8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_DLLHijack_GXP_2147975362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.GXP!MTB"
        threat_id = "2147975362"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 f8 4e 69 c0 ?? ?? ?? ?? 89 c7 c1 ef 0b 31 c7 89 3a 89 d7 8b 45 e4 89 30 8b 30 85 f6}  //weight: 5, accuracy: Low
        $x_5_2 = {8b 45 e8 8b 4d 0c c1 c0 07 33 45 f0 03 07 8b 55 ec 31 c2 89 11 33 01}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_CAT_2147975764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.CAT!MTB"
        threat_id = "2147975764"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {e8 02 00 00 00 eb 05 58 89 04 24 c3 a0 ?? ?? ?? 10 3c a5 0f 84}  //weight: 10, accuracy: Low
        $x_5_2 = {c8 ff ff ff 0f 0b 0f 00 c0 0f 00 c8 0f 00 d0 0f 00 d8 0f 01 04 24 0f 01 0c 24 0f 01 14 24 0f 01 1c 24 0f 01 c1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DLLHijack_ASYB_2147975867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DLLHijack.ASYB!MTB"
        threat_id = "2147975867"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DLLHijack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 ec bf c8 01 00 00 8b 75 08 8b 48 08 8b 45 14 03 4d 10 0f b6 04 06 46 99 f7 ff 89 75 08 b8 ?? ?? ?? ?? 80 c2 36 30 11 c3 8b 75 10 b8 67 66 66 66 f7 ee 8b 5d ec 8b ce 8b 7d 0c c1 fa 02 8b c2 c7 45 fc ff ff ff ff c1 e8 1f 03 c2 8d 04 80 03 c0 2b c8 f7 d9 1b c9 21 4d 08 46 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

