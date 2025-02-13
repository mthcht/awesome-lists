rule TrojanDownloader_Win32_Waski_A_2147743723_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waski.A!MTB"
        threat_id = "2147743723"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 06 8b 55 ?? c1 c2 ?? 03 f2 8b 0e c1 c1 ?? 83 e1 ?? 03 c1 4b 89 07 ba ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 03 fa 85 db 0f 84 ?? ?? ?? ?? 8b 06 8b 55 ?? c1 ca ?? 03 f2 8b 0e c1 c1 ?? 83 e1 ?? 03 c1 4b 89 07 ba ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 03 fa 85 db 75}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 03 03 c6 ba ?? ?? ?? ?? 81 f2 ?? ?? ?? ?? 03 da 2d ?? ?? ?? ?? 89 45 ?? 03 cd 51 e8 ?? ?? ?? ?? 57 59 59 2b cd 8b 55 ?? 81 f2 ?? ?? ?? ?? 03 d1 3b d1 0f 85 ?? ?? ?? ?? 2b d1 49 3b ca 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Waski_SIBA_2147787487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waski.SIBA!MTB"
        threat_id = "2147787487"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ce 3b c8 74 ?? ff 45 ?? 83 7d 01 ?? 7c ?? 83 7d 01 03 0f 84 ?? ?? ?? ?? 80 3e ?? 75 ?? 80 7e ?? ?? 75 ?? 80 7e ?? ?? 75 ?? 38 5e ?? 75 ?? c1 e0 ?? 50 6a ?? ff 75 ?? ff 15 ?? ?? ?? ?? 89 45 ?? 3b c3 0f 84 ?? ?? ?? ?? 8b 7d ?? 8b 45 ?? 8b 40 ?? 8b d7 33 c9 83 e7 ?? c1 e2 ?? 41 89 5d ?? 83 ff ?? 76 ?? 31 04 8e 8b 7d 16 41 c1 ef ?? 3b cf 72 ?? 83 6d 16 ?? 8d 45 1b 50 ff 75 16 83 c6 ?? 56 8b 75 14 52 56 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Waski_SIBC_2147787488_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waski.SIBC!MTB"
        threat_id = "2147787488"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 8b f5 b9 ?? ?? ?? ?? ad 60 8b e8 8b f3 b9 10 00 00 00 e8 ?? ?? ?? ?? b9 1f 00 00 00 e8 ?? ?? ?? ?? 56 b9 07 00 00 00 e8 ?? ?? ?? ?? 8b d0 8b 34 24 b9 09 00 00 00 e8 ?? ?? ?? ?? 8b fe 8b ca e8 ?? ?? ?? ?? 33 c0 50 c1 c8 ?? c1 04 24 ?? 01 04 24 ac 84 c0 75 ?? 58 8b f7 3b c5 74 ?? 4a 75 ?? 8b 34 24 b9 0a 00 00 00 e8 ?? ?? ?? ?? 0f b7 0c 56 5e 51 b9 08 00 00 00 e8 ?? ?? ?? ?? 59 e8 ?? ?? ?? ?? 89 74 24 ?? 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Waski_GEM_2147811651_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waski.GEM!MTB"
        threat_id = "2147811651"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 0c c1 e8 02 2b c1 50 f7 f3 83 c2 02 29 16 33 d2 58 f7 f3 03 14 24 81 c2 22 fa 87 35 31 16 83 c6 04 e2 d9}  //weight: 10, accuracy: High
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "Do you realy want me?" ascii //weight: 1
        $x_1_4 = "My name is Hero and my dick is brilliant" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Waski_GTM_2147811652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waski.GTM!MTB"
        threat_id = "2147811652"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 10 8b 14 85 10 30 40 00 33 c0 8b cf 40 c1 e9 02 3b c8 76 08 31 14 83 40 3b c1 72 f8}  //weight: 10, accuracy: High
        $x_1_2 = "/looks/777_2305USmw_1.zip" ascii //weight: 1
        $x_1_3 = "rseomat.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Waski_GT_2147814284_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waski.GT!MTB"
        threat_id = "2147814284"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {33 00 2b f0 8b 55 f8 c1 c2 16 52 c3 2b d3 8b ff 8b 16 3b d7 72 9e}  //weight: 10, accuracy: High
        $x_1_2 = "Sajlilespilvi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Waski_XI_2147821723_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waski.XI!MTB"
        threat_id = "2147821723"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {57 8d 64 24 ?? 8b 52 ?? 83 3c 82 ?? 8d 04 4e 52 8b 16 4f 8b 07 47 33 d0 46 ff 0c 24 8a c6 46 aa 58 8b d0 85 c0 ?? ?? 8b 45 ?? 8b 55 ?? 8b f0 e2 dd 41}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Waski_AW_2147839750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waski.AW!MTB"
        threat_id = "2147839750"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 8d 44 24 44 50 68 dc 21 40 00 50 ff 15 ?? ?? ?? ?? 83 c4 10 8d 44 24 40 55 55 55 50 e9 ?? ?? ?? ?? 56 33 f6 39 74 24 08 76 ?? 8a 04 16 88 04 0e 46 3b 74 24 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Waski_GNZ_2147896101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waski.GNZ!MTB"
        threat_id = "2147896101"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {80 f2 f1 c0 c2 03 80 ea 05 80 f2 03 56}  //weight: 10, accuracy: High
        $x_10_2 = {8b 4c 24 0c 8b 5c 24 04 8b c3 03 c1 83 e8 01 8a 00 8b 54 24 08 03 d1 88 42 ff e2 ec c2 0c 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Waski_ARA_2147903730_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Waski.ARA!MTB"
        threat_id = "2147903730"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Waski"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {ba 00 00 00 00 8b 45 0c c1 e8 02 2b c1 50 f7 f3 42 42 29 16 33 d2 58 f7 f3 03 14 24 52 81 04 24 21 ec 30 45 5a 31 16 83 c6 04 e2 d4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

