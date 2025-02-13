rule VirTool_Win32_CryptInject_YA_2147731462_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CryptInject.YA!MTB"
        threat_id = "2147731462"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 00 8b 4d f4 8a 04 08 88 45 f0 8b 45 08 8b 00 8b 4d f4 8a 44 01 01 88 45 f3 8b 45 08 8b 00 8b 4d f4 8a 44 01 02 88 45 f1 8b 45 08 8b 00 8b 4d f4 8a 44 01 03 88 45 f2 0f b6 45 f0 0f b6 4d f2 c1 e1 02 81 e1 c0 00 00 00 0b c1 88 45 f0 0f b6 45 f3 0f b6 4d f2 c1 e1 04 81 e1 c0 00 00 00 0b c1 88 45 f3 0f b6 45 f1 0f b6 4d f2 c1 e1 06 81 e1 c0 00 00 00 0b c1 88 45 f1 8b 45 f8 03 45 fc 8a 4d f0 88 08 8b 45 fc 40 89 45 fc 8b 45 f8 03 45 fc 8a 4d f3 88 08 8b 45 fc 40 89 45 fc 8b 45 f8 03 45 fc 8a 4d f1 88 08 8b 45 fc 40 89 45 fc e9 31 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CryptInject_YC_2147731659_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CryptInject.YC!MTB"
        threat_id = "2147731659"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 00 03 c3 8a 08 88 4d 13 8a 48 01 88 4d ff 8a 48 02 0f b6 40 03 50 8d 45 fe 50 8d 45 ff 50 8d 45 13 50 88 4d fe e8 8f ff ff ff 8a 45 13 88 04 3e 8a 45 ff 88 44 3e 01 8a 45 fe 88 44 3e 02 8b 45 0c 83 c3 04 83 c6 03 3b 18 72 b1}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 8a 45 14 8b 4d 08 8a d0 80 e2 f0 c0 e2 02 08 11 8b 4d 0c 8a d0 80 e2 fc c0 e2 04 08 11 8b 4d 10 c0 e0 06 08 01 5d c2 10 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CryptInject_YD_2147731880_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CryptInject.YD!MTB"
        threat_id = "2147731880"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 08 8b 00 8b 4d f8 03 c1 8a 08 88 4d ff 8a 48 01 88 4d fe 8a 48 02 8a 40 03 88 4d fd 8d 4d fd 8d 75 fe 8d 7d ff e8 4e ff ff ff 8b 45 f4 8a 4d ff 83 45 f8 04 88 0c 03 8a 4d fe 43 88 0c 03 8a 4d fd 43 88 0c 03 8b 45 0c 8b 4d f8 43 3b 08 72 ae}  //weight: 1, accuracy: High
        $x_1_2 = {8a d0 80 e2 f0 c0 e2 02 08 17 8a d0 80 e2 fc c0 e2 04 08 16 c0 e0 06 08 01 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CryptInject_YE_2147732008_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CryptInject.YE!MTB"
        threat_id = "2147732008"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 93 03 45 99 89 45 c5 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 c1 8d 9d ?? fd ff ff 53 ff 55 c1 89 45 9d 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 cd 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 d1 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 c9 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 d5 8d 9d ?? fd ff ff 53 ff 75 99 ff 55 c5 89 45 d9 8d 9d ?? fd ff ff 53 ff 75 9d ff 55 c5 89 45 dd 8d 9d ?? fd ff ff 53 ff 55 c1 89 45 a1 8d 9d ?? fd ff ff 53 ff 75 a1 ff 55 c5 89 45 e1 8d 9d ?? fd ff ff 53 ff 75 a1 ff 55 c5 89 45 e5 8d 9d ?? fd ff ff 53 ff 75 a1 ff 55 c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CryptInject_L_2147733848_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CryptInject.L"
        threat_id = "2147733848"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pdf_reader.crt" ascii //weight: 1
        $x_1_2 = "sqllite.dll" ascii //weight: 1
        $x_1_3 = "\\m.dll" ascii //weight: 1
        $x_1_4 = "\\aap.ppk" ascii //weight: 1
        $x_1_5 = "\\pdf.exe" ascii //weight: 1
        $x_1_6 = "ekrn.exe" wide //weight: 1
        $x_1_7 = "egui.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CryptInject_2147743844_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CryptInject!MTB"
        threat_id = "2147743844"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 7e 14 08 ff 00 66 0f 6e d3 50 00 5b 50 00 ff 34 08}  //weight: 1, accuracy: Low
        $x_1_2 = {66 0f 7e 14 08 [0-112] 83 e9 fc [0-80] 81 f9 ?? ?? 00 00 0f 85 ?? ?? ff ff [0-255] 66 0f ef d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CryptInject_2147743844_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CryptInject!MTB"
        threat_id = "2147743844"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {83 c1 04 0f 8d ?? ?? ff ff ff 00 ff 34 0f [0-48] 5b [0-48] 31 f3 [0-48] 89 1c 0a [0-64] 83 e9 08 [0-48] 83 c1 04 0f 8d ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CryptInject_2147743844_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CryptInject!MTB"
        threat_id = "2147743844"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {83 ff 00 0f 8d ?? ?? ff ff 50 00 29 df 50 00 8f 04 38 50 00 ff 75 34 50 00 31 75 34 50 00 8f 45 34 50 00 ff 34 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CryptInject_2147743844_3
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CryptInject!MTB"
        threat_id = "2147743844"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 8b 45 08 e8 ?? ?? ?? ?? ff 45 f8 81 7d f8 ?? ?? ?? ?? 75 e7}  //weight: 1, accuracy: Low
        $x_1_2 = {88 4d f7 89 55 f8 89 45 fc 8b 45 fc 03 45 f8 73 05 e8 ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 8a 00 88 45 ?? 8b 45 ?? 89 45 ?? 8a 45 ?? 30 45 f7 8b 45 ?? 8a 55 f7 88 10 8b e5 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_CryptInject_2147743844_4
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/CryptInject!MTB"
        threat_id = "2147743844"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = {66 0f 6e c6 [0-16] 66 0f 6e c9 [0-16] c5 f0 57 c8 [0-16] 66 0f 7e c9 [0-16] 39 c1 0f 77 [0-16] 46 [0-16] ff 37 [0-16] 59}  //weight: 1, accuracy: Low
        $x_1_3 = {66 0f 6e c6 [0-16] 66 0f 6e c9 [0-16] 66 0f ef c8 [0-16] 66 0f 7e c9 [0-16] 39 c1 0f 77 [0-16] 46 [0-16] ff 37 [0-16] 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

