rule Ransom_Win32_Magniber_MB_2147763329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Magniber.MB!MTB"
        threat_id = "2147763329"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 28 33 ff 03 ea 83 c0 ?? 89 44 24 ?? c1 cf ?? 0f be 45 00 03 f8 45 80 7d ff ?? 75 f0 8d 04 37 3b 44 24 ?? 74 20 8b 44 24 ?? 43 3b 5c 24 ?? 72 cf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Magniber_AZ_2147843263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Magniber.AZ!MTB"
        threat_id = "2147843263"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_100_2 = {41 8a 08 41 ba fe 00 00 00 32 cb 80 c3 ff 88 0a 48 ff c2 84 db 0f b6 cb 41 0f 44 ca 49 ff c0 8a d9 49 ff c9 75 da 48 83 c4 20 5b 48 ff e0}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Magniber_AB_2147843648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Magniber.AB!MTB"
        threat_id = "2147843648"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 0c e9 05 00 8b 4d 0c ac 02 c3 32 c3 c0 c8 ?? aa 49 0f 85 ?? ?? ?? ?? 5e 5f 5a 59 5b c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Magniber_A_2147848588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Magniber.A!!Magniber.gen!A"
        threat_id = "2147848588"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "Magniber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 33 c0 4c 8b d1 b8 ?? 00 00 00 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 58 eb [0-128] 48 83 e8 05 eb [0-128] 48 2d ?? ?? ?? 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 4c 77 d6 07 e8 ?? ?? ?? ?? 48 8d [0-8] ff d0 b9 49 f7 02 78 4c 8b e0 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {ff d0 b9 3a 56 29 a8 e8 ?? ?? ?? ?? b9 77 87 2a f1 48 89 ?? ?? e8 ?? ?? ?? ?? b9 d3 6b 6e d4}  //weight: 1, accuracy: Low
        $x_1_5 = {74 6d dd 6e c7 45 ?? 07 c0 75 4e 48 c7 ?? ?? 00 02 00 00 48 89 ?? ?? c7 44 ?? ?? 00 10 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Magniber_A_2147848588_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Magniber.A!!Magniber.gen!A"
        threat_id = "2147848588"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "Magniber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e c3 [0-48] b8 ?? ?? 00 00 0f 05 c3 [0-48] b8 ?? ?? 00 00 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 58 48 83 e8 05 48 2d ?? ?? ?? 00 c3}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 4c 77 d6 07 e8 ?? ?? ?? ?? 48 8d [0-8] ff d0 b9 49 f7 02 78 4c 8b e0 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {ff d0 b9 3a 56 29 a8 e8 ?? ?? ?? ?? b9 77 87 2a f1 48 89 ?? ?? e8 ?? ?? ?? ?? b9 d3 6b 6e d4}  //weight: 1, accuracy: Low
        $x_1_5 = {74 6d dd 6e c7 45 ?? 07 c0 75 4e 48 c7 ?? ?? 00 02 00 00 48 89 ?? ?? c7 44 ?? ?? 00 10 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Magniber_A_2147848588_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Magniber.A!!Magniber.gen!A"
        threat_id = "2147848588"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "Magniber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e c3 [0-48] b8 ?? ?? 00 00 0f 05 c3 [0-48] b8 ?? ?? 00 00 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 00 00 00 00 58 eb [0-48] 48 83 e8 05 eb [0-48] 48 2d ?? ?? ?? 00 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 4c 77 d6 07 e8 ?? ?? ?? ?? 48 8d [0-8] ff d0 b9 49 f7 02 78 4c 8b e0 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {ff d0 b9 3a 56 29 a8 e8 ?? ?? ?? ?? b9 77 87 2a f1 48 89 ?? ?? e8 ?? ?? ?? ?? b9 d3 6b 6e d4}  //weight: 1, accuracy: Low
        $x_1_5 = {74 6d dd 6e c7 45 ?? 07 c0 75 4e 48 c7 ?? ?? 00 02 00 00 48 89 ?? ?? c7 44 ?? ?? 00 10 00 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Magniber_A_2147848588_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Magniber.A!!Magniber.gen!A"
        threat_id = "2147848588"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "Magniber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e c3 [0-6] b8 ?? ?? 00 00 0f 05 c3 [0-6] b8 ?? ?? 00 00 0f 05 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 69 00 6e 00 6e 00 74 00 00 00 2e 00 00 00 2e 00 2e 00 00 00 5c 00 00 00 52 00 45 00 41 00 44 00 4d 00 45 00 2e 00 68 00 74 00 6d 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "= new Array(" ascii //weight: 1
        $x_1_4 = "fromCharCode" ascii //weight: 1
        $x_1_5 = {e8 00 00 00 00 58 48 83 e8 05 48 2d ?? ?? 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_6 = {b9 4c 77 d6 07 e8 ?? ?? ?? ?? 48 8d [0-8] ff d0 b9 49 f7 02 78 4c 8b e0 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_Magniber_RPY_2147850588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Magniber.RPY!MTB"
        threat_id = "2147850588"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Magniber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 a8 fd ff ff 0f b7 8c 45 ac fd ff ff 83 f9 20 75 52 8b 85 a8 fd ff ff 0f b7 8c 45 ae fd ff ff 83 f9 2f 75 3f 8b 85 a8 fd ff ff 0f b7 8c 45 b0 fd ff ff 83 f9 64 75 2c 8b 85 a8 fd ff ff 0f b7 8c 45 b2 fd ff ff 83 f9 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

