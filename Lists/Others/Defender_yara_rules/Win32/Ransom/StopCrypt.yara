rule Ransom_Win32_StopCrypt_SK_2147756302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SK!MTB"
        threat_id = "2147756302"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 1f 33 4d ?? 89 35 ?? ?? ?? ?? 33 4d ?? 89 4d ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ec 8b 45 ?? 8b 4d ?? 31 08 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SK_2147756302_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SK!MTB"
        threat_id = "2147756302"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 8b 85 30 ff ff ff 81 45 d4 aa a4 ab 79 81 45 70 39 2d 8e 45 81 85 24 ff ff ff a6 98 53 58 81 6d 08 9e b9 8b 52 81 ad b0 fe ff ff 03 72 47 4d}  //weight: 2, accuracy: High
        $x_2_2 = {f7 65 b0 8b 45 b0 81 45 0c ?? ?? ?? ?? 81 ad fc fe ff ff ?? ?? ?? ?? 81 45 bc ?? ?? ?? ?? 8b 85 80 00 00 00 30 0c 30 b8 01 00 00 00 83 f0 04 83 ad 80 00 00 00 01 39 bd 80 00 00 00 0f 8d ?? ?? ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SM_2147760355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SM!MTB"
        threat_id = "2147760355"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 4d fc 89 4d ?? 8b 45 ?? 01 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 c1 e0 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 03 45 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SM_2147760355_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SM!MTB"
        threat_id = "2147760355"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c5 d3 e0 8b cd c1 e9 ?? 03 4c 24 ?? 03 44 24 ?? 89 35 ?? ?? ?? ?? 33 c1 8b 4c 24 ?? 03 cd 33 c1 29 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {53 8b 19 55 8b 69 04 56 33 f6 81 3d ?? ?? ?? ?? ?? ?? 00 00 57 8b fa 89 4c 24 ?? 89 5c 24 ?? 75}  //weight: 1, accuracy: Low
        $x_1_3 = {56 57 8b f1 8b fa 81 3d ?? ?? ?? ?? ?? ?? 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 54 24 ?? 8b ce e8 ?? ?? ?? ?? 83 c6 08 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SP_2147760700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SP!MTB"
        threat_id = "2147760700"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd.exe /C ping 1.1.1.1 -n 3 -w 3000 > Nul & Del /f /q \"%s\"" wide //weight: 2
        $x_2_2 = "testers.exe" ascii //weight: 2
        $x_2_3 = "Allie detected" ascii //weight: 2
        $x_2_4 = "AU3!" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SP_2147760700_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SP!MTB"
        threat_id = "2147760700"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 39 8b f0 81 e6 ?? ?? ?? ?? 33 f7 c1 e8 08 8b 34 b5 ?? ?? ?? ?? 33 c6 41 4a 75 e3}  //weight: 1, accuracy: Low
        $x_1_2 = "Infected with a virous" wide //weight: 1
        $x_1_3 = "info.txt" wide //weight: 1
        $x_1_4 = "wbadmin delete systemstatebackup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MK_2147773609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MK!MTB"
        threat_id = "2147773609"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 70 89 45 [0-1] 8b 85 b0 fe ff ff 01 45 00 8b 7d 70 8b 4d 6c 33 5d 00 d3 ef c7 05 [0-8] 03 bd a4 fe ff ff 33 fb 81 3d [0-6] 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MK_2147773609_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MK!MTB"
        threat_id = "2147773609"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 c1 e1 [0-1] 03 8d [0-2] ff ff 81 3d [0-6] 00 00 8b 5d [0-1] 03 d8 c1 e8 [0-1] 89 45 [0-1] c7 05 [0-8] 8b 85 [0-2] ff ff 01 45 [0-1] 81 3d [0-6] 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MK_2147773609_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MK!MTB"
        threat_id = "2147773609"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptionwinapi\\Salsa20.inl" ascii //weight: 1
        $x_1_2 = "bowsakkdestx.txt" ascii //weight: 1
        $x_1_3 = "C:\\SystemID\\PersonalID.txt" ascii //weight: 1
        $x_1_4 = "Time Trigger Task" ascii //weight: 1
        $x_1_5 = "Trigger1" ascii //weight: 1
        $x_1_6 = "--AutoStart" ascii //weight: 1
        $x_1_7 = "delself.bat" ascii //weight: 1
        $x_1_8 = "expand 32-byte k" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SN_2147774375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SN!MTB"
        threat_id = "2147774375"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 81 45 ?? ?? ?? ?? ?? 31 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SN_2147774375_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SN!MTB"
        threat_id = "2147774375"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 85 ff 7e ?? eb ?? 8d 49 00 e8 ?? ?? ff ff 30 04 16 42 3b d7 7c}  //weight: 2, accuracy: Low
        $x_2_2 = {50 6a 00 ff 15 ?? ?? ?? ?? a3 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? eb ?? c7 85 ?? ?? ?? ?? 00 00 00 00 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_KM_2147776152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.KM!MTB"
        threat_id = "2147776152"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 84 0d 44 [0-3] 4a 32 03 41 88 07 43 47 3b ce 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SL_2147778281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SL!MTB"
        threat_id = "2147778281"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 c1 ef 05 03 7d e8 c1 e0 04 03 45 e4 89 4d f8 33 f8 33 f9 89 7d 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 08 8b 45 08 c1 e0 04 03 c6 89 45 f4 8b 45 08 03 45 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {51 c7 45 fc ?? ?? ?? ?? 8b 45 0c 90 01 45 fc 83 6d fc ?? 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_SL_2147778281_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SL!MTB"
        threat_id = "2147778281"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 8b ec 53 56 57 51 64 ff 35 30 00 00 00 58 8b 40 0c 8b 48 0c 8b 11 8b 41 30 6a 02 8b 7d ?? 57 50 e8 ?? 00 00 00 85 c0 74}  //weight: 2, accuracy: Low
        $x_2_2 = {55 8b ec 83 ec ?? 53 56 57 8b 45 ?? c6 00 00 83 65 ?? 00 e8 00 00 00 00 58 89 45 ?? 81 45 ?? ?? ?? ?? ?? 8b 45 ?? 8b 4d ?? 89 48 ?? 8b 45 ?? 83 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MAK_2147784054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MAK!MTB"
        threat_id = "2147784054"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 8b c8 c1 e9 05 03 4c 24 20 03 c7 33 c8 33 4c 24 34 c7 05 [0-8] 89 4c 24 34 8b 44 24 34 01 05 [0-4] 2b f1 8b ce c1 e1 04 03 fe 8b d6 57 8d 44 24 38 03 cb c1 ea 05 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MBK_2147785015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MBK!MTB"
        threat_id = "2147785015"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 1c 01 c1 e8 05 89 45 [0-1] c7 05 [0-8] 8b 85 90 fd ff ff 01 45 00 81 3d [0-6] 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 74 31 45 [0-1] 89 3d [0-4] 8b 45 [0-1] 29 45 [0-1] 81 3d [0-6] 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MBK_2147785015_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MBK!MTB"
        threat_id = "2147785015"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 5d fc 89 75 ec 25 [0-4] 81 6d ec [0-4] 81 45 ec [0-4] 8b 4d dc 8b c3 c1 e8 [0-1] 89 45 fc 8d 45 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 5d f8 89 7d e8 25 [0-4] 81 6d e8 [0-4] 81 45 e8 [0-4] 8b 4d dc 8b c3 c1 e8 [0-1] 89 45 f8 8d 45 f8}  //weight: 1, accuracy: Low
        $x_1_3 = {33 45 f4 89 7d ec 2b d8 25 [0-4] 81 6d ec [0-4] 81 45 ec [0-4] 8b 4d d4 8b c3 c1 e8 [0-1] 89 45 f4 8d 45 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_MZK_2147785421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MZK!MTB"
        threat_id = "2147785421"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 75 0c c7 05 [0-8] 33 75 f8 89 75 f4 8b 45 f4 01 05 [0-4] 8b 45 f0 2b fe 8b f7 c1 e6 [0-1] 03 75 e8 03 c7 81 3d [0-4] be 01 00 00 89 45 0c 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MZK_2147785421_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MZK!MTB"
        threat_id = "2147785421"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 c1 e8 ?? 89 45 ec 8b 45 ec 03 45 d4 89 45 ec 8b 45 e4 33 45 f0 89 45 e4 8b 45 e4 33 45 ec 89 45 e4 8b 45 e4 29 45 d0 ff 75 d8 8d 45 e8 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MYK_2147785422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MYK!MTB"
        threat_id = "2147785422"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 45 0c 8b 4d 08 c1 e0 04 89 01 5d c2}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 8b 45 10 8b 4d 08 c1 e8 05 03 45 0c 89 01 5d c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MYK_2147785422_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MYK!MTB"
        threat_id = "2147785422"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 01 45 00 83 3d ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 01 45 00 81 3d ?? ?? ?? ?? ?? ?? 00 00 75}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 1c 01 8b 4d 6c d3 e8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 85 80 fe ff ff 01 45 01 8b 55 01 33 d3 33 55 64 8d 8d}  //weight: 1, accuracy: Low
        $x_1_4 = {8d 1c 10 d3 ea c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 55 ?? 8b 85 04 fe ff ff 01 45 01 8b 4d 01 33 cb 33 4d e8 8d 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_MWK_2147786816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MWK!MTB"
        threat_id = "2147786816"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d1 31 55 ?? 8b 55 00 8d 8d ?? ?? ?? ?? e8 ?? ?? ?? ?? 83 3d ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MWK_2147786816_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MWK!MTB"
        threat_id = "2147786816"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 29 45 f4 25 [0-4] 8b 45 f4 8b 55 fc 8b c8 03 d0 c1 e9 [0-1] 03 4d d8 c1 e0 [0-1] 03 45 dc 52 89 4d f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MVK_2147786885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MVK!MTB"
        threat_id = "2147786885"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e9 05 89 4d ec 8b 55 ec 03 55 d4 89 55 ec 8b 45 e4 33 45 f0 89 45 e4 8b 4d e4 33 4d ec 89 4d e4 8b 45 e4 29 45 d0 8b 55 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MVK_2147786885_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MVK!MTB"
        threat_id = "2147786885"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 33 44 24 [0-1] c2 [0-2] 81 00 [0-4] c3}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 89 01 c3 81 00 [0-4] c3 29 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_MQK_2147787569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MQK!MTB"
        threat_id = "2147787569"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 55 ?? 8b 85 08 fe ff ff 01 45 01 8b 4d 01 33 cb 33 4d e8 8d 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MPK_2147788276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MPK!MTB"
        threat_id = "2147788276"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 55 ec 8b 45 ec 03 45 d4 89 45 ec 8b 4d e4 33 4d f0 89 4d e4 8b 55 e4 33 55 ec 89 55 e4 8b 45 e4}  //weight: 1, accuracy: High
        $x_1_2 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 e4 33 45 ec 89 45 e4 8b 4d e4}  //weight: 1, accuracy: High
        $x_1_3 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 ec 50 8d 4d e4}  //weight: 1, accuracy: High
        $x_1_4 = {d3 e0 89 45 f8 8b 45 d0 01 45 f8 8b 4d d4 8b c3 c1 e8 [0-1] 89 45 f4 8d 45 f4}  //weight: 1, accuracy: Low
        $x_1_5 = {d3 e0 89 45 f8 8b 45 d0 01 45 f8 8b 4d d4 8b c2 c1 e8 [0-1] 89 45 f4 8d 45 f4}  //weight: 1, accuracy: Low
        $x_1_6 = {d3 e0 89 45 fc 8b 45 d4 01 45 fc 8b 4d d8 8b c2 c1 e8 [0-1] 89 45 f8 8d 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_MRK_2147792997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MRK!MTB"
        threat_id = "2147792997"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e0 89 45 fc 8b 45 d8 01 45 fc 8b 4d d4 8b c2 c1 e8 [0-1] 89 45 ec 8d 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MRK_2147792997_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MRK!MTB"
        threat_id = "2147792997"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 8b fe d3 ef 89 45 f4 03 7d d8 33 f8 81 fa [0-4] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d dc 8b c3 c1 e8 ?? 89 45 f0 8d 45 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_MSK_2147793257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MSK!MTB"
        threat_id = "2147793257"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3}  //weight: 1, accuracy: High
        $x_1_2 = {33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 33 44 24 04 c2 04 00 81 00 [0-4] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MSK_2147793257_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MSK!MTB"
        threat_id = "2147793257"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f4 c1 e2 [0-1] 89 55 e4 8b 45 f8 01 45 e4 8b 45 f4 03 45 e8 89 45 f0 c7 05 [0-8] c7 05 [0-4] ff ff ff ff 8b 45 f4 8b 8d 40 ff ff ff d3 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MUK_2147793447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MUK!MTB"
        threat_id = "2147793447"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 f0 89 44 24 10 89 74 24 1c 8b 44 24 1c 01 05 [0-4] 8b 44 24 1c 29 44 24 14 8b 44 24 14 c1 e0 [0-1] 89 44 24 10 8b 44 24 30 01 44 24 10 8b 44 24 14 03 44 24 20 89 44 24 18 81 3d [0-6] 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MUK_2147793447_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MUK!MTB"
        threat_id = "2147793447"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 5d f4 89 75 f8 25 [0-4] 81 6d f8 [0-4] 81 45 f8 [0-4] 8b 4d dc 8b c3 c1 e8 [0-1] 89 45 f4 8d 45 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 fc 8b 4d f0 03 c7 89 45 e8 8b c7 d3 e8 8b 4d d4 c7 05 [0-8] 89 45 f4 8d 45 f4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_2147793452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MTK!MTB"
        threat_id = "2147793452"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTK: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 33 08 8b 55 08 89 0a 5d c2}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 8b 45 0c c1 e0 [0-1] 8b 4d 08 89 01 5d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_2147793452_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MTK!MTB"
        threat_id = "2147793452"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTK: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 33 44 24 18 c7 05 [0-8] 33 f0 89 44 24 10 89 74 24 1c 8b 44 24 1c 01 05 [0-4] 8b 44 24 1c 29 44 24 14 8b 4c 24 14 c1 e1 [0-1] 89 4c 24 10 8b 44 24 28 01 44 24 10 8b 44 24 14 03 44 24 20 89 44 24 18 81 3d [0-6] 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PA_2147793710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PA!MTB"
        threat_id = "2147793710"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 01 08 c3}  //weight: 1, accuracy: High
        $x_1_2 = {2b 5d fc 89 75 ec 25 [0-4] 81 6d ec [0-4] 81 45 ec [0-4] 8b 4d [0-2] 8b c3 c1 e8 05 89 45 ?? 8d 45 ?? e8 [0-4] 8b 45 ?? 8b 4d ?? 03 c3 50 8b c3 d3 e0 03 45 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MCK_2147793715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MCK!MTB"
        threat_id = "2147793715"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 65 f0 00 2b df 25 [0-4] 81 6d f0 [0-4] 81 45 f0 [0-4] 8b 4d dc 8b c3 c1 e8 [0-1] 89 45 ec 8d 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MDK_2147793997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MDK!MTB"
        threat_id = "2147793997"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 33 08 8b 55 08 89 0a 5d c2}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 51 c7 45 fc [0-4] 8b 45 0c 8b 4d fc d3 e0 8b 4d 08 89 01 8b e5 5d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MEK_2147794024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MEK!MTB"
        threat_id = "2147794024"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 45 f0 89 5d f4 2b f8 25 [0-4] 81 6d f4 [0-4] 81 45 f4 [0-4] 8b 4d dc 8b c7 c1 e8 [0-1] 89 45 f0 8d 45 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MFK_2147794173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MFK!MTB"
        threat_id = "2147794173"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 89 4d e4 8b 45 f8 01 45 e4 8b 45 f4 03 45 e8 89 45 f0 c7 05 [0-8] c7 05 [0-8] 8b 55 f4 8b 8d [0-4] d3 ea 89 55 ec 8b 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PD_2147794264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PD!MTB"
        threat_id = "2147794264"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "jjjjjjjj" wide //weight: 1
        $x_1_2 = {8b 45 d0 2b 45 e4 89 45 d0 8b 4d d8 51 8d 55 e8 52 e8 [0-4] e9 [0-4] 8b 45 08 8b 4d d0 89 08 8b 55 08 8b 45 f4 89 42 04 81 [0-16] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MGK_2147794300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MGK!MTB"
        threat_id = "2147794300"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 8b 4d 0c 33 08 8b 55 08 89 0a 5d c2}  //weight: 1, accuracy: High
        $x_1_2 = {55 8b ec 8b 45 08 8b 08 33 4d 0c 8b 55 08 89 0a 5d c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_MHK_2147794387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MHK!MTB"
        threat_id = "2147794387"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d ec 33 c8 89 45 f4 2b f9 25 [0-4] 8b c7 8d 4d f4 e8 [0-4] 8b 4d d4 8b c7 c1 e8 [0-1] 89 45 ec 8d 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MIK_2147794606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MIK!MTB"
        threat_id = "2147794606"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 c7 45 fc [0-4] 8b 45 0c 01 45 fc 8b 45 08 8b 4d fc 33 08 8b 55 08 89 0a 8b e5 5d c2}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 c7 45 fc [0-4] 8b 45 0c 01 45 fc 8b 45 08 8b 08 33 4d fc 8b 55 08 89 0a 8b e5 5d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_MJK_2147794786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MJK!MTB"
        threat_id = "2147794786"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f0 33 c8 89 45 f8 2b f9 25 [0-4] 8b c7 8d 4d f8 e8 [0-4] 8b 4d d8 8b c7 c1 e8 [0-1] 89 45 f0 8d 45 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d f0 33 c8 89 45 f8 2b f9 25 [0-4] 8b c7 8d 4d f8 e8 [0-4] 8b 4d e0 8b c7 c1 e8 [0-1] 89 45 f0 8d 45 f0}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4d f8 33 c8 89 45 fc 2b f9 25 [0-4] 8b c7 8d 4d fc e8 [0-4] 8b 4d e0 8b c7 c1 e8 [0-1] 89 45 f8 8d 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_PE_2147795079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PE!MTB"
        threat_id = "2147795079"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 ?? 8b 08 33 4d ?? 8b 55 ?? 89 0a 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e2 04 89 ?? e4 8b 45 f8 01 45 e4 8b 45 f4 03 45 e8 89 45 f0 c7 05 [0-10] c7 05 [0-10] 8b ?? f4 8b 8d [0-4] d3 ?? 89 ?? ec 8b ?? ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PG_2147795225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PG!MTB"
        threat_id = "2147795225"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 ?? 33 45 ?? 8b 4d ?? 89 01 5d}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? c7 05 ?? ?? ?? ?? fc 03 cf ff 8b 4d ?? 51 8d 55 ?? 52 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PF_2147795302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PF!MTB"
        threat_id = "2147795302"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 c8 c1 fa 05 8b 45 c8 83 e0 1f c1 e0 06 03 [0-6] 89 45 c0 eb [0-4] c7 45 ?? ?? 7b 42 00 8b 4d c0 8a 51 24 d0 e2 d0 fa 0f be c2 85 c0 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MKK_2147795327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MKK!MTB"
        threat_id = "2147795327"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 8b d6 d3 ea 89 45 f0 03 55 dc 33 d0 89 55 ec 8b 45 ec 29 45 f8 25 [0-4] 8b 55 f8 8b c2 8d 4d f0 e8 [0-4] 8b 4d e0 8b c2 c1 e8 [0-1] 89 45 ec 8d 45 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MLK_2147795874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MLK!MTB"
        threat_id = "2147795874"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 45 ec 8b 4d ec 03 4d d4 89 4d ec 8b 55 e4 33 55 f0 89 55 e4 8b 45 ec 31 45 e4 8b 45 d0 2b 45 e4 89 45 d0 81 3d [0-6] 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PB_2147796230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PB!MTB"
        threat_id = "2147796230"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 bb 52 c0 5d 81 6d ?? 36 dd 96 53 81 45 ?? 3a dd 96 53 8b 4d dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MMK_2147796542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MMK!MTB"
        threat_id = "2147796542"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 45 f4 89 45 e8 8b 45 f4 29 45 f0 25 [0-4] 8b 55 f0 8b c2 8d 4d e8 e8 [0-4] 8b 4d f8 03 ca c1 ea [0-1] 89 55 f4 8b 45 dc 01 45 f4 8b 45 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PH_2147796629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PH!MTB"
        threat_id = "2147796629"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 31 08 c3 81 3d ?? ?? ?? ?? e6 01 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 04 33 44 24 08 c2 08 00 81 00 fe 36 ef c6 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PL_2147796696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PL!MTB"
        threat_id = "2147796696"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 31 08 c3 81 3d ?? ?? ?? ?? e6 01 00 00 75 ?? 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 04 33 44 24 08 c2 08 00 81 00 08 37 ef c6 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MNK_2147796738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MNK!MTB"
        threat_id = "2147796738"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 fa d3 ea 89 7c 24 24 89 54 24 14 8b 44 24 34 01 44 24 14 8b 44 24 24 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 28 89 4c 24 10 e8 ?? ?? ?? ?? 8d 44 24 20 e8 ?? ?? ?? ?? 83 eb 01 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MNK_2147796738_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MNK!MTB"
        threat_id = "2147796738"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 c7 45 fc [0-4] 8b 45 0c 8b 4d fc d3 e8 8b 4d 08 89 01 8b e5 5d c2}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 c7 45 fc [0-4] 8b 45 10 01 45 fc 8b 45 0c 33 45 fc 8b 4d 08 89 01 8b e5 5d c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_MOK_2147797328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MOK!MTB"
        threat_id = "2147797328"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 [0-1] c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PM_2147797462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PM!MTB"
        threat_id = "2147797462"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 04 00 c1 e0 04 89 01 c3 83 3d ?? ?? ?? ?? 7e}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 04 31 06 c2 04 00 33 44 24 04 c2 04 00 81 00 12 37 ef c6 c3 01 08 c3 29 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MAPK_2147797722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MAPK!MTB"
        threat_id = "2147797722"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 51 c7 45 fc [0-4] 8b 45 10 8b 4d fc d3 e8 8b 4d 08 89 01 8b 55 08 8b 02 03 45 0c 8b 4d 08 89 01 8b e5 5d c2}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 e4 33 45 f0 89 45 e4 8b 4d ec 33 4d e4 89 4d ec c7 05 [0-8] 8b 45 ec 01 05 [0-4] 8b 45 ec 29 45 f4 8b 55 f4 c1 e2 04 89 55 e4 8b 45 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_MAQK_2147797723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MAQK!MTB"
        threat_id = "2147797723"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 d3 ee 89 45 f0 03 75 d8 33 f0 2b fe 25 [0-4] 8b c7 8d 4d f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PC_2147797734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PC!MTB"
        threat_id = "2147797734"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 31 08 c3 33 44 24 04 c2 04 00 81 00 cc 36 ef c6 c3 01 08 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PN_2147797773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PN!MTB"
        threat_id = "2147797773"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff 15 [0-4] 33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 33 44 24 04 c2 04 00 81 00 ?? ?? ?? ?? c3 01 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PN_2147797773_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PN!MTB"
        threat_id = "2147797773"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 ff 15 [0-4] 33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 29 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PQ_2147798041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PQ!MTB"
        threat_id = "2147798041"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 33 44 24 04 89 01 c2 04 00 33 44 24 04 c2 04 00 81 00 ?? 36 ef c6 c3 01 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PR_2147798175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PR!MTB"
        threat_id = "2147798175"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3 55 8b ec 83 ec 0c}  //weight: 1, accuracy: High
        $x_1_2 = {c2 08 00 33 44 24 04 c2 04 00 81 00 ae 36 ef c6 c3 01 08 c3 55 8b ec 81 ec 28 0c 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PS_2147798601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PS!MTB"
        threat_id = "2147798601"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 89 01 c3}  //weight: 1, accuracy: High
        $x_1_2 = {c2 08 00 33 44 24 04 c2 04 00 81 00 ?? 36 ef c6 c3 01 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PT_2147799259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PT!MTB"
        threat_id = "2147799259"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 50 50 50 50 50 ff 15 ?? ?? ?? ?? 33 74 24 0c 8b 44 24 08 89 30 5e c2 08 00 33 44 24 04 c2 04 00 81 00 40 36 ef c6 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PU_2147799378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PU!MTB"
        threat_id = "2147799378"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 44 24 04 c2 04 00 81 00 ?? 36 ef c6 c3 55 8b ec 81 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PV_2147805547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PV!MTB"
        threat_id = "2147805547"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 44 24 04 c2 04 00 81 00 40 36 ef c6 c3 55 8b ec 81 ec 28 0c 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PW_2147806129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PW!MTB"
        threat_id = "2147806129"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 04 00 81 00 a4 36 ef c6 c3 29 08 c3 55 8b ec 81 ec 48}  //weight: 1, accuracy: High
        $x_1_2 = {c1 e8 05 03 45 ?? 03 fa 33 cf 33 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MXK_2147807318_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MXK!MTB"
        threat_id = "2147807318"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 05 [0-4] 89 01 c3 [0-5] 01 08 c3 [0-13] 31 08 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MZA_2147808361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MZA!MTB"
        threat_id = "2147808361"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 03 33 f9 8b 4d [0-1] d3 e8 c7 05 [0-8] 03 45 [0-1] 33 c7 83 3d [0-5] 89 45 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {25 bb 52 c0 5d 8b 4d [0-1] 8b d1 c1 e2 [0-1] 03 55 [0-1] 8b c1 c1 e8 [0-1] 03 45 [0-1] 03 cb 33 d1 33 d0 89 55 [0-1] 89 35 [0-4] 8b 45 [0-1] 29 45 [0-1] 81 c3 [0-4] ff 4d ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_MZB_2147808821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MZB!MTB"
        threat_id = "2147808821"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 8b 4c 24 08 31 08 c2 [0-2] 8b 44 24 04 8b 4c 24 08 01 08 c2 [0-2] 8b 44 24 08 8b 4c 24 04 c1 e0 [0-1] 89 01 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MZC_2147808961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MZC!MTB"
        threat_id = "2147808961"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 03 c8 33 f9 8b 4d [0-1] d3 e8 89 7d [0-1] c7 05 [0-8] 03 45 [0-1] 33 c7 8b f8 83 fa [0-1] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c3 c1 e0 [0-1] 03 45 e8 89 45 fc 8b 45 f8 03 c3 89 45 d8 8b 45 d8 31 45 fc 8b c3 c1 e8 [0-1] 03 45 dc 89 35 [0-4] 31 45 fc 8b 45 fc 29 45 f4 8b 45 e4 29 45 f8 ff 4d ec 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_MZD_2147809043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MZD!MTB"
        threat_id = "2147809043"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e0 [0-1] 03 45 d4 89 45 f8 8d 04 0b 89 45 d8 8b 45 d8 31 45 f8 c1 e9 [0-1] 03 4d e0 89 3d [0-4] 31 4d f8 8b 45 f8 29 45 f0 81 c3 [0-4] ff 4d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAD_2147809079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAD!MTB"
        threat_id = "2147809079"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 00 47 86 c8 61 c3 81 00 a4 36 ef c6 c3 55 8b ec 81 ec 44 08 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAF_2147809474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAF!MTB"
        threat_id = "2147809474"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 00 47 86 c8 61 c3 55}  //weight: 1, accuracy: High
        $x_1_2 = {c2 0c 00 81 00 03 35 ef c6 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAF_2147809474_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAF!MTB"
        threat_id = "2147809474"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 45 e4 89 75 ec 8b 45 fc 01 45 ec 8b 45 e4 01 45 ec 8b 45 ec 89 45 f0 8b 45 e4 8b 4d e8 d3 e8 89 45 f8 8b 45 cc 01 45 f8 8b 7d e4 c1 e7 ?? 03 7d d8 33 7d f0}  //weight: 1, accuracy: Low
        $x_1_2 = {33 ca 31 4d 0c c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 0c 01 05 ?? ?? ?? ?? 2b 75 0c c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b ce c1 e1 ?? 03 4d ec 8b c6 c1 e8 ?? 03 45 e4 8d 14 33 33 ca 33 c8 2b f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_PAG_2147809569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAG!MTB"
        threat_id = "2147809569"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 08 8b 45 f0 83 25 ?? ?? ?? ?? ?? 03 c8 33 4d 08 33 4d 0c 89 4d 08 8b 45 08 01 05 ?? ?? ?? ?? 2b 7d 08 89 7d fc 8b 45 fc 03 45 f8 89 45 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAG_2147809569_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAG!MTB"
        threat_id = "2147809569"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b c7 c1 e8 05 03 44 24 ?? 03 cd 33 c1 8d 0c 3b 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 14 c7 05}  //weight: 10, accuracy: Low
        $x_1_2 = {33 cb 33 c1 2b f8 8d 44 24 1c e8 ?? ?? ?? ?? ff 4c 24 18 0f 85}  //weight: 1, accuracy: Low
        $x_1_3 = {33 d3 33 c2 2b f8 8d 44 24 1c e8 ?? ?? ?? ?? ff 4c 24 18 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_StopCrypt_MZE_2147809584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MZE!MTB"
        threat_id = "2147809584"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 14 03 8b 45 f0 c1 e8 05 89 45 f8 8b 45 f8 03 45 dc 33 ca 33 c1 81 3d ?? ?? ?? ?? 13 02 00 00 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f8 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MZE_2147809584_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MZE!MTB"
        threat_id = "2147809584"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f4 03 cf 33 d1 8b 4d [0-1] 8b f7 d3 ee c7 05 [0-8] 89 55 [0-1] 03 75 [0-1] 33 f2 83 f8 [0-1] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4d f0 8b c1 c1 e0 [0-1] 03 45 e0 89 45 fc 8b 45 f4 03 c1 89 45 dc 8b 45 dc 31 45 fc ff 75 fc c1 e9 [0-1] 03 4d d8 8d 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_PAJ_2147809912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAJ!MTB"
        threat_id = "2147809912"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 68 [0-4] ff [0-6] 83 65 [0-2] 8b 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 8b 4d 08 89 01 c9 c2 [0-2] 81 00 03 35 ef c6 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAL_2147810212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAL!MTB"
        threat_id = "2147810212"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 10 89 45 ?? 8b 45 0c 31 45 ?? 8b 45 ?? 8b 4d 08 89 01 [0-2] c9 c2 0c 00 81 00 03 35 ef c6 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MZF_2147810232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MZF!MTB"
        threat_id = "2147810232"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 8d 0c 03 8b 45 [0-1] c1 e8 [0-1] 89 45 [0-1] 8b 45 [0-1] 33 f1 8b 4d [0-1] 03 c1 33 c6 83 3d [0-4] 27 c7 05 [0-8] 89 45 fc 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAH_2147810520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAH!MTB"
        threat_id = "2147810520"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 04 8b 4c 24 08 29 08 c2 [0-2] 8b 44 24 04 8b 4c 24 08 29 08 c2 [0-2] 55 8b ec 51 83 65 fc ?? 8b 45 ?? 01 45 ?? 8b 45 08 8b 4d ?? 31 08 c9 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAM_2147810521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAM!MTB"
        threat_id = "2147810521"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 00 03 35 ef c6 c3 01 08 c3 55 8b ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAN_2147810526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAN!MTB"
        threat_id = "2147810526"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 03 8b 45 [0-2] c1 e8 05 89 45 ?? 8b 45 ?? 33 f1 8b [0-5] 03 c1 33 c6 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91 89 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAO_2147810758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAO!MTB"
        threat_id = "2147810758"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c8 8b 45 ?? c1 e8 05 89 45 ?? 8b 45 ?? 33 f1 8b 8d ?? ?? ?? ?? 03 c1 33 c6 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91 89 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAQ_2147810895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAQ!MTB"
        threat_id = "2147810895"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {81 00 03 35 ef c6 c3 55 8b ec}  //weight: 4, accuracy: High
        $x_1_2 = {03 c1 33 c7 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91}  //weight: 1, accuracy: Low
        $x_1_3 = {03 c1 33 c6 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_StopCrypt_PAR_2147811166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAR!MTB"
        threat_id = "2147811166"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {81 00 f9 34 ef c6 c3 55 8b ec 81 ec}  //weight: 4, accuracy: High
        $x_1_2 = {03 c1 33 c6 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91}  //weight: 1, accuracy: Low
        $x_1_3 = {03 c3 33 c7 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_StopCrypt_PAS_2147811439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAS!MTB"
        threat_id = "2147811439"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 08 88 0a c3}  //weight: 1, accuracy: High
        $x_1_2 = {cc cc cc cc cc cc cc cc cc cc cc 33 c9 c7 40 18 0f 00 00 00 89 48 14 88 48 04 c3}  //weight: 1, accuracy: High
        $x_3_3 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4c ?? ?? 30 04 31 81 ff ?? ?? ?? ?? 75}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MZG_2147811529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MZG!MTB"
        threat_id = "2147811529"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 45 fc 8b 45 fc 8b 4d 08 89 01 5e c9 c2 [0-2] 33 44 24 04 c2 [0-2] 81 00 [0-4] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAT_2147811636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAT!MTB"
        threat_id = "2147811636"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {33 44 24 04 c2 04 00 81 00 ?? 34 ef c6 c3 55 8d 6c 24 ?? 81 ec}  //weight: 3, accuracy: Low
        $x_1_2 = {03 c1 33 c7 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91}  //weight: 1, accuracy: Low
        $x_1_3 = {03 c1 33 c6 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_StopCrypt_PAU_2147811870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAU!MTB"
        threat_id = "2147811870"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c1 33 c7 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAV_2147811871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAV!MTB"
        threat_id = "2147811871"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 47 86 c8 61 c3 33 44 24 04 c2 04 00 81 00 ?? 34 ef c6 c3 55 8d 6c 24 ?? 81 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAW_2147812182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAW!MTB"
        threat_id = "2147812182"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 00 47 86 c8 61 c3 [0-96] 81 00 f5 34 ef c6 c3 55}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 eb c7 05 [0-4] 2e ce 50 91 89 45 ?? 03 [0-6] 33 d8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAX_2147812225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAX!MTB"
        threat_id = "2147812225"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\encrypt_win_api.pdb" ascii //weight: 2
        $x_1_2 = "delself.bat" ascii //weight: 1
        $x_1_3 = "--AutoStart" wide //weight: 1
        $x_1_4 = " /deny *S-1-1-0:(OI)(CI)(DE,DC)" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PAY_2147812866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAY!MTB"
        threat_id = "2147812866"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c3 81 00 47 86 c8 61 c3}  //weight: 1, accuracy: High
        $x_1_2 = {c2 08 00 81 00 ?? 34 ef c6 c3}  //weight: 1, accuracy: Low
        $x_4_3 = {d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 85 ?? ?? ?? ?? 33 c3 81 3d ?? ?? ?? ?? b7 01}  //weight: 4, accuracy: Low
        $x_4_4 = {d3 eb c7 05 ?? ?? ?? ?? ee 3d ea f4 03 9d ?? ?? ?? ?? 33 da 81 3d ?? ?? ?? ?? b7 01}  //weight: 4, accuracy: Low
        $x_4_5 = {d3 e8 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 45 [0-4] 33 c2 89 45 ?? 81 fe a3 01}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_StopCrypt_PAZ_2147813730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PAZ!MTB"
        threat_id = "2147813730"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ca 31 4d ?? 8b 4d ?? d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 ?? 33 55 ?? 89 55 ?? 3d a3 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBB_2147815410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBB!MTB"
        threat_id = "2147815410"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 d3 e2 8b 4d ?? 8b c7 d3 e8 03 95 ?? ?? ?? ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 8d 04 3e 33 45 ?? 89 1d ?? ?? ?? ?? 33 d0 8b ca 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 c6 47 86 c8 61 ff 8d ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBC_2147815433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBC!MTB"
        threat_id = "2147815433"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 e2 8b 4d ?? 8b c6 d3 e8 03 95 ?? ?? ?? ?? 89 45 ?? 8b 85 ?? ?? ?? ?? 01 45 ?? 83 25 ?? ?? ?? ?? 00 8d 04 37 33 45 ?? 33 d0 8b ca 8d 85 ?? ?? ?? ?? e8 ?? ?? ?? ?? 81 c7 47 86 c8 61 ff 8d ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ce c1 e9 05 c7 05 [0-10] 89 4c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b c6 c1 e0 04 03 44 24 ?? 8d 14 33 33 c2 33 44 24 ?? 81 c3 47 86 c8 61 2b f8 83 6c 24 ?? 01 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_PBD_2147816020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBD!MTB"
        threat_id = "2147816020"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 05 c7 05 ?? ?? ?? ?? b4 21 e1 c5 89 45 ?? 8b 45 ?? 01 45 ?? ff 75 ?? 8b c7 c1 e0 04 03 45 ?? 8d 0c 3b 33 c1 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBH_2147816713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBH!MTB"
        threat_id = "2147816713"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 03 45 [0-6] c1 e1 04 03 4d ?? 50 03 f3 8d 45 ?? 33 ce 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 89 4d ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBH_2147816713_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBH!MTB"
        threat_id = "2147816713"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 03 45 ?? c1 e1 04 03 4d ?? 50 03 d6 8d 45 ?? 33 ca 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 89 4d ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 03 45 [0-6] c1 e1 04 03 4d ?? 50 03 d3 8d 45 ?? 33 ca 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 89 4d ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_PBI_2147816906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBI!MTB"
        threat_id = "2147816906"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c3 81 00 e1 34 ef c6 c3 55 8b ec}  //weight: 1, accuracy: High
        $x_1_2 = {b8 fe 93 8d 6a 33 ca 31 4d ?? 81 3d ?? ?? ?? ?? a3 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBG_2147816917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBG!MTB"
        threat_id = "2147816917"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = {5d c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3 c7 05 ?? ?? ?? ?? 88 61 4d 00 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBA_2147817072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBA!MTB"
        threat_id = "2147817072"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a 00 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 30 04 31 81 bc 24 ?? ?? ?? ?? 91 05 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBJ_2147817290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBJ!MTB"
        threat_id = "2147817290"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c2 04 00 81 00 e1 34 ef c6 c3 55 8b ec}  //weight: 1, accuracy: High
        $x_1_2 = {03 c7 33 45 ?? 33 c1 81 3d ?? ?? ?? ?? a3 01 00 00 89 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBK_2147817306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBK!MTB"
        threat_id = "2147817306"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b fe 8b 75 ?? 8b d7 c1 e2 ?? 03 55 ?? 8b c7 c1 e8 05 03 45 ?? 03 f7 33 d6 33 d0 2b da 81 3d [0-8] 00 00 c7 05 ?? ?? ?? ?? b4 21 e1 c5 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBL_2147817731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBL!MTB"
        threat_id = "2147817731"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c3 33 f0 33 75 ?? 89 75 ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 83 0d [0-6] 2b fe 8b c7 c1 e0 04 03 45 ?? 8b d7 89 45 ?? 8b 45 ?? 03 c7 50 8d 45 ?? c1 ea 05 03 55 ?? 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBM_2147817954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBM!MTB"
        threat_id = "2147817954"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 04 3b 33 44 24 ?? 33 c1 81 3d [0-8] 89 44 24 ?? 75}  //weight: 3, accuracy: Low
        $x_3_2 = {8d 04 3b 33 44 24 ?? 33 c1 83 3d [0-8] 89 44 24 ?? 75}  //weight: 3, accuracy: Low
        $x_1_3 = {2b f0 8b d6 d3 ea}  //weight: 1, accuracy: High
        $x_1_4 = {33 d6 2b fa 81 c3 47 86 c8 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_StopCrypt_PMA_2147817959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PMA!MTB"
        threat_id = "2147817959"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 f8 83 [0-6] 2b fe 8b cf c1 e1 04 03 4d e8 8b c7 c1 e8 05 03 45 f4 03 d7 33 ca 33 c8 68 [0-4] 8d 45 f8 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBN_2147818071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBN!MTB"
        threat_id = "2147818071"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e0 04 03 45 ?? 8b d7 89 45 ?? 8d 04 3e 50 8d 45 ?? c1 ea 05 03 55 ?? 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 e8 [0-4] 8b 45 [0-8] 33 c2 29 45 [0-6] 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBO_2147818155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBO!MTB"
        threat_id = "2147818155"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 33 c2 81 3d [0-10] 89 44 24 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {2b d8 8b c3 d3 e8 89 9c 24 ?? ?? ?? ?? 03 d3 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? c1 e3 04 03 9c 24 ?? ?? ?? ?? 33 da 81 3d [0-10] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBO_2147818155_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBO!MTB"
        threat_id = "2147818155"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 33 c2 83 3d [0-8] 89 44 24 ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {2b f0 8b c6 d3 e8 89 74 24 ?? 03 d6 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? c1 e6 04 03 b4 24 ?? ?? ?? ?? 33 f2 81 3d [0-8] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PMB_2147818357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PMB!MTB"
        threat_id = "2147818357"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 0c c1 ea ?? 03 55 e8 50 c7 05 [0-8] e8 [0-4] 31 55 0c 2b 5d 0c 68 b9 79 37 9e 8d 45 fc 50 e8 [0-4] ff 4d f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_RPI_2147818464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.RPI!MTB"
        threat_id = "2147818464"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 0c 03 8b 45 f4 03 c6 33 c8 33 4d f8 89 4d f8 8b 45 f8}  //weight: 1, accuracy: High
        $x_1_2 = {2b f9 8b c7 c1 e0 04 03 45 ec 8b d7 89 45 f8 8b 45 f4 03 c7 c1 ea 05 03 55 e0 50 8d 4d f8}  //weight: 1, accuracy: High
        $x_1_3 = {8b 45 08 89 78 04 5f 89 30 5e 5b c9 c2 04 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBP_2147819035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBP!MTB"
        threat_id = "2147819035"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 50 50 50 ff 15 ?? ?? ?? ?? 8b 45 ?? 83 25 ?? ?? ?? ?? 00 81 45 ?? 47 86 c8 61 33 c3 2b f8 ff [0-6] 89 [0-6] 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBP_2147819035_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBP!MTB"
        threat_id = "2147819035"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f1 8b ce c1 e1 04 03 4d ?? 8b c6 c1 e8 05 03 45 ?? 8d 14 33 33 ca 33 c8 2b f9 81 c3 47 86 c8 61 ff 4d ?? c7 05 [0-10] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBQ_2147819709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBQ!MTB"
        threat_id = "2147819709"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b cf c1 e9 05 03 4d ?? 03 c2 33 c8 8d 04 3b 33 c8 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 83 0d [0-6] 2b f1 8b ce c1 e1 04 03 4d ?? 8b c6 c1 e8 05 03 45 ?? 8d 14 33 33 ca 33 c8 2b f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBR_2147819829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBR!MTB"
        threat_id = "2147819829"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 5d ?? c1 e3 04 03 5d ?? 33 5d ?? 81 3d [0-10] 75 ?? 33 c0 50 50 50 ff 15 ?? ?? ?? ?? 8b 45 ?? 83 25 [0-8] 33 c3 2b f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBS_2147820121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBS!MTB"
        threat_id = "2147820121"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 45 ?? 8b 45 ?? 01 45 ?? 8b 7d ?? c1 e7 04 03 7d ?? 33 7d ?? 81 3d ?? ?? ?? ?? 21 01 00 00 75 [0-32] 33 7d ?? 89 35 ?? ?? ?? ?? 89 7d ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBT_2147820125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBT!MTB"
        threat_id = "2147820125"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 31 4d ?? c7 05 [0-10] 8b 45 ?? 01 05 ?? ?? ?? ?? 2b 75 ?? c7 05 [0-10] 8b ce c1 e1 04 03 4d ?? 8b c6 c1 e8 05 03 45 ?? 8d 14 33 33 ca 33 c8 2b f9 81 3d [0-10] c7 05 [0-10] 89 45 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBU_2147820395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBU!MTB"
        threat_id = "2147820395"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e6 04 03 74 24 ?? 33 74 24 ?? 81 3d [0-10] 75 [0-16] 33 74 24 ?? c7 05 [0-10] 89 74 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? 47 86 c8 61 ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBV_2147820475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBV!MTB"
        threat_id = "2147820475"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 d0 89 54 24 ?? 8b 44 24 ?? c1 e8 05 89 44 24 ?? 8b 44 24 ?? 33 4c 24 ?? 03 44 24 ?? c7 05 [0-10] 33 c1 81 3d [0-10] 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBW_2147821726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBW!MTB"
        threat_id = "2147821726"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c8 31 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 2b 75 ?? 83 0d [0-8] 8b c6 c1 e8 05 03 45 ?? 8b ce c1 e1 04 03 4d ?? 50 89 45 ?? 8d 14 33 8d 45 ?? 33 ca 50 c7 05 [0-10] 89 4d ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBX_2147821917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBX!MTB"
        threat_id = "2147821917"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b cb c1 e1 04 03 4c 24 ?? 89 15 ?? ?? ?? ?? 33 4c 24 ?? 33 4c 24 ?? 2b f9 89 7c 24 ?? 8b 44 24 ?? 29 44 24 ?? ff 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBY_2147824171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBY!MTB"
        threat_id = "2147824171"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 03 4d ?? 8b 45 ?? 03 45 ?? 89 45 ?? 8b 55 ?? 83 0d [0-8] 81 45 ?? 47 86 c8 61 8b c2 c1 e8 05 03 45 ?? c7 05 [0-10] 33 45 ?? 33 c1 2b f0 ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PBZ_2147825061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PBZ!MTB"
        threat_id = "2147825061"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce c1 e9 05 03 4d ?? 03 fb 03 c6 33 cf 33 c8 89 45 ?? 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 4d ?? c1 e1 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PCA_2147825861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PCA!MTB"
        threat_id = "2147825861"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 [0-10] 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 81 45 ?? 47 86 c8 61 33 c1 2b f0 ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PCB_2147825886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PCB!MTB"
        threat_id = "2147825886"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 44 24 ?? 03 c5 33 c1 83 3d [0-8] c7 05 [0-10] 89 4c 24 ?? 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PCC_2147826068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PCC!MTB"
        threat_id = "2147826068"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 44 24 ?? 03 44 24 ?? c7 05 [0-10] 33 c1 83 3d [0-8] 89 4c 24 ?? 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PCD_2147826852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PCD!MTB"
        threat_id = "2147826852"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 c7 05 [0-10] 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 33 45 ?? 33 c8 89 4d ?? 8b 45 ?? 29 45 ?? 81 45 ?? 47 86 c8 61 ff 4d ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PCF_2147827793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PCF!MTB"
        threat_id = "2147827793"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 55 ?? c1 e0 04 03 45 ?? 89 4d ?? 33 d0 33 d1 89 55 ?? 8b 45 [0-16] 8b 45 ?? 29 45 ?? 8b 45 ?? c1 e0 04 03 45 ?? 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLJ_2147828781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLJ!MTB"
        threat_id = "2147828781"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 20 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 33 54 24 ?? 8d 4c 24 ?? 89 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 2c c1 e8 05 89 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 ?? 01 44 24 ?? 33 74 24 ?? 31 74 24 ?? 83 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PCG_2147828910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PCG!MTB"
        threat_id = "2147828910"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 33 74 24 ?? 03 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c6 83 3d ?? ?? ?? ?? 0c 89 44 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLK_2147828975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLK!MTB"
        threat_id = "2147828975"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ce c1 e9 ?? 03 4d ?? 8b d6 c1 e2 ?? 03 55 ?? 03 c6 33 ca 33 c8 89 45 ?? 89 4d 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 ?? 8b 45 ?? c1 e0 ?? 03 c3 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLM_2147829036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLM!MTB"
        threat_id = "2147829036"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 89 3d ?? ?? ?? ?? 33 d1}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 44 24 04 ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 31 04 24 8b 04 24 83 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLN_2147829179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLN!MTB"
        threat_id = "2147829179"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 89 74 24 ?? 03 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 8b 4c 24 ?? d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 33 54 24 ?? 8d 4c 24 ?? 89 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLO_2147829180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLO!MTB"
        threat_id = "2147829180"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 d3 e2 89 5c 24 ?? 03 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b c7 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 89 1d ?? ?? ?? ?? 33 d1 8d 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLP_2147829252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLP!MTB"
        threat_id = "2147829252"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 89 1d ?? 33 d1 8d 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {89 0c 24 c7 44 24 04 ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 31 04 24 8b 04 24 83 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLQ_2147829573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLQ!MTB"
        threat_id = "2147829573"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b de c1 e3 ?? 03 5d ?? 8d 04 32 33 cb 33 c8 89 45 ?? 89 4d ?? 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? c1 e0 ?? 03 45 ?? 89 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 f4 33 45 ?? 83 65 ?? ?? 2b f0 8b 45 ?? 01 45 ?? 2b 55 ?? ff 4d ?? 89 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLR_2147829662_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLR!MTB"
        threat_id = "2147829662"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 d3 ea 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 54 24 ?? 8b ce e8 ?? ?? ?? ?? 33 44 24 ?? 89 1d ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? ba ?? ?? ?? ?? 8d 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {83 ec 0c 89 54 24 ?? 89 0c 24 c7 44 24 04 ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 31 04 24 8b 04 24 83 c4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLS_2147829674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLS!MTB"
        threat_id = "2147829674"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca c1 e9 ?? 03 4d ?? 8b da c1 e3 ?? 03 5d ?? 8d 04 16 33 cb 33 c8 89 45 ?? 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? c1 e0 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 03 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 0c 01 45 ?? 83 6d fc ?? 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_PCE_2147829676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.PCE!MTB"
        threat_id = "2147829676"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 4c 24 ?? 33 74 24 ?? 03 4c 24 ?? c7 05 [0-10] 33 ce 83 3d [0-8] 89 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLT_2147829740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLT!MTB"
        threat_id = "2147829740"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 d3 e6 89 5c 24 ?? 03 74 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 8b d7 d3 ea 89 54 24 ?? 8b 44 24 ?? 01 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {33 44 24 10 89 1d ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 28 ?? ?? ?? ?? 4d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLU_2147829806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLU!MTB"
        threat_id = "2147829806"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca 8b c2 c1 e8 ?? c1 e1 ?? 03 4d ?? 03 c3 33 c1 33 45 ?? 89 45 ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? c1 e0 ?? 03 c7 89 45 ?? 8b 45 ?? 03 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 0c 01 45 ?? 83 6d fc ?? 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLV_2147829811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLV!MTB"
        threat_id = "2147829811"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 44 24 10 89 2d ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 c3 ?? ?? ?? ?? ff 4c 24 ?? 89 5c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {89 44 24 18 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? c1 e8 ?? 89 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 ?? 01 44 24 ?? 8b 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLW_2147829928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLW!MTB"
        threat_id = "2147829928"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 89 3d ?? 31 4c 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 2c ?? ?? ?? ?? 4b}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 18 c1 e8 ?? 89 44 24 ?? 8b 54 24 ?? 01 54 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 83 3d ?? ?? ?? ?? 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_SLA_2147829986_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLA!MTB"
        threat_id = "2147829986"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e0 ?? 03 45 ?? 8d 0c 16 33 c1 89 4d ?? 8b ca c1 e9 ?? 03 4d ?? 89 45 ?? 33 c8 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLB_2147829987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLB!MTB"
        threat_id = "2147829987"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 f8 89 45 ?? 8b 55 ?? 8b 4d ?? d3 e2 8b 45 ?? 33 c2 89 45 ?? 8b 4d ?? 03 4d ?? 8b 55 ?? 0b d1 89 55 ?? 83 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {2b c8 89 4d ?? 8b 55 ?? 6b d2 ?? 8b 45 ?? 0b c2 89 45 ?? 8b 4d ?? 83 f1 ?? 8b 55 ?? 33 d1 89 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MKSS_2147830002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MKSS!MTB"
        threat_id = "2147830002"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e0 ?? 03 45 ?? 8d 0c 16 33 c1 89 4d f4 8b ca c1 e9 ?? 03 4d ?? 89 45 ?? 33 c8 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLC_2147830099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLC!MTB"
        threat_id = "2147830099"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 d3 ea 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 89 3d ?? ?? ?? ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 31 4c 24 ?? 83 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLD_2147830197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLD!MTB"
        threat_id = "2147830197"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 89 35 ?? ?? ?? ?? 31 4c 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 29 44 24 ?? ff 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 89 44 24 ?? 8b 54 24 ?? 01 54 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 83 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLF_2147830363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLF!MTB"
        threat_id = "2147830363"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 33 44 24 ?? 89 35 ?? ?? ?? ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 4b}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 31 4c 24 ?? 83 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLG_2147830489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLG!MTB"
        threat_id = "2147830489"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 14 01 44 24 ?? 8b 54 24 ?? 8b 4c 24 ?? d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 33 54 24 ?? 83 3d ?? ?? ?? ?? 0c 89 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLH_2147830490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLH!MTB"
        threat_id = "2147830490"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 c1 e0 ?? 03 45 ?? 8d 0c 17 33 c1 89 4d ?? 8b ca c1 e9 ?? 03 4d ?? 89 45 ?? 33 c8 89 4d ?? 8b 45 ?? 01 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLI_2147830621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLI!MTB"
        threat_id = "2147830621"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 30 33 4c 24 ?? 89 35 ?? ?? ?? ?? 31 4c 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 2c ?? ?? ?? ?? 83 ef}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 33 54 24 ?? 83 3d ?? ?? ?? ?? 0c 89 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLX_2147830622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLX!MTB"
        threat_id = "2147830622"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 84 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 66 ?? 3d 45 66 89 84 24 ?? ?? ?? ?? 39 4c 24 ?? 73 ?? 8b 44 24 ?? 8b 4c 24 ?? 8a 54 04 ?? 88 54 0c ?? 8b 44 24 ?? 83 c0 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLY_2147830716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLY!MTB"
        threat_id = "2147830716"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 03 4d ?? c1 e8 ?? 03 45 ?? 33 ca 33 c1 89 55 ?? 89 4d ?? 89 45 ?? 8b 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 0c 83 6d fc ?? ?? 01 45 ?? 83 6d fc ?? 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SLZ_2147830717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SLZ!MTB"
        threat_id = "2147830717"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 30 33 4c 24 ?? 89 35 ?? ?? ?? ?? 31 4c 24 ?? 8b 44 24 ?? 29 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 33 54 24 ?? 83 3d ?? ?? ?? ?? 0c 89 54 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SA_2147830840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SA!MTB"
        threat_id = "2147830840"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 d3 ea 8d 4c 24 ?? 89 54 24 ?? 8b 54 24 ?? e8 ?? ?? ?? ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 54 24 ?? 33 d1 8d 4c 24 ?? 89 54 24 ?? 89 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ee c7 05 ?? ?? ?? ?? ee 3d ea f4 03 74 24 ?? 8b 44 24 ?? 31 44 24 ?? 33 74 24 ?? 83 3d ?? ?? ?? ?? 0c 89 74 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SB_2147830841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SB!MTB"
        threat_id = "2147830841"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 c1 e1 ?? 03 4d ?? c1 e8 ?? 33 ca 03 c3 33 c1 89 55 ?? 89 4d ?? 89 45 ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 0c 83 6d fc ?? ?? 01 45 ?? 83 6d fc ?? 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SC_2147831002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SC!MTB"
        threat_id = "2147831002"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8b 44 24 ?? 33 c1 2b f0 ba ?? ?? ?? ?? 8d 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SD_2147831003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SD!MTB"
        threat_id = "2147831003"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 8d 14 06 c1 e1 ?? 03 4d ?? c1 e8 ?? 03 45 ?? 33 ca 33 c1 89 4d ?? 89 45 ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SE_2147831185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SE!MTB"
        threat_id = "2147831185"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 04 03 4d ?? c1 e8 ?? 03 45 ?? 33 ce 33 c1 89 4d ?? 89 45 ?? 8b 45 ?? 01 05}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 45 0c 83 6d ?? ?? ?? 01 45 ?? 83 6d ?? ?? 8b 45 ?? 8b 4d ?? 31 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_StopCrypt_SF_2147831193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SF!MTB"
        threat_id = "2147831193"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 4c 24 ?? 33 4c 24 28 8b 44 24 ?? 33 c1 2b f0 ba ?? ?? ?? ?? 8d 4c 24 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SG_2147831194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SG!MTB"
        threat_id = "2147831194"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 10 33 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 31 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 01 05 ?? ?? ?? ?? 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? c1 e0 ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SH_2147831302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SH!MTB"
        threat_id = "2147831302"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 3c 01 44 24 ?? 8b 54 24 ?? 33 54 24 ?? 8b 44 24 ?? 81 44 24 ?? ?? ?? ?? ?? 33 c2 2b f0 83 eb ?? 89 44 24 ?? 89 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SI_2147831379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SI!MTB"
        threat_id = "2147831379"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 37 c1 ee ?? 03 75 ?? 03 c3 33 c1 33 f0 89 4d ?? 89 45 ?? 89 75 ?? 8b 45 ?? 01 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_RPL_2147831762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.RPL!MTB"
        threat_id = "2147831762"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d3 e0 89 45 e4 8b 4d e4 03 4d f8 89 4d e4 8b 55 f4 03 55 e8 89 55 f0 c7 85 3c ff ff ff 00 00 00 00 8b 45 f4 c1 e8 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SJ_2147831935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SJ!MTB"
        threat_id = "2147831935"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 33 45 ?? 8d 0c 1f 33 c8 89 45 ?? 89 4d ?? 89 35 ?? ?? ?? ?? 8b 45 ?? 01 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_RPV_2147832140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.RPV!MTB"
        threat_id = "2147832140"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7d f0 8b c7 c1 e0 04 03 45 e0 89 45 f8 8b 45 f0 03 45 f4 89 45 0c ff 75 0c}  //weight: 1, accuracy: High
        $x_1_2 = {ff 4d ec 8b 4d fc 0f 85 ?? ?? ?? ?? 8b 45 08 89 78 04 5f 5e 89 08 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SO_2147832633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SO!MTB"
        threat_id = "2147832633"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 0c 07 33 4d ?? 89 35 ?? ?? ?? ?? 33 4d ?? 89 4d ?? 8b 45 ?? 01 05}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e8 05 03 45 ?? 68 ?? ?? ?? ?? 33 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 c7 2b d8 8d 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SQ_2147833083_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SQ!MTB"
        threat_id = "2147833083"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SS_2147833084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SS!MTB"
        threat_id = "2147833084"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 45 f8 8b 4d ?? 33 4d ?? 8b 45 ?? 33 c1 2b f8 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_ST_2147833192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.ST!MTB"
        threat_id = "2147833192"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 45 0c 33 f8 89 7d ?? 8b 45 ?? 29 45 ?? 89 75 ?? 8b 45 ?? 01 45 ?? 2b 5d ?? ff 4d ?? 89 5d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SU_2147833602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SU!MTB"
        threat_id = "2147833602"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 45 ec 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 29 45 ?? 89 75 ?? 8b 45 ?? 01 45 ?? 2b 7d ?? ff 4d ?? 8b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SV_2147833786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SV!MTB"
        threat_id = "2147833786"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f0 d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 33 5d ?? 31 5d ?? 83 3d ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SW_2147834067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SW!MTB"
        threat_id = "2147834067"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 29 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SY_2147834149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SY!MTB"
        threat_id = "2147834149"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e2 89 3d ?? ?? ?? ?? 03 55 ?? 33 55 ?? 33 d6 89 55 ?? 8b 45 ?? 29 45 ?? 8d 45 ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SZ_2147834403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SZ!MTB"
        threat_id = "2147834403"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 33 5d ?? 31 5d ?? 83 3d ?? ?? ?? ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_TA_2147834700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.TA!MTB"
        threat_id = "2147834700"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? 89 45 ?? 8d 45 ?? e8 ?? ?? ?? ?? 8b 45 ?? 33 c7 31 45 ?? 89 35 ?? ?? ?? ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MNP_2147835424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MNP!MTB"
        threat_id = "2147835424"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4d ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 f8 8d 45 f8 e8 ?? ?? ?? ?? 8b 45 ?? 31 45 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c2 d3 e8 89 35 ?? ?? ?? ?? 03 45 ?? 89 45 f8 33 c7 31 45 fc 8b 45 ?? 89 45 ?? 8b 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MKS_2147835430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MKS!MTB"
        threat_id = "2147835430"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 33 45 ?? 89 45 ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? c1 e0 ?? 03 c7 89 45 f4 8b 45 ?? 03 45 ?? 89 45 fc 8b 45 ?? 83 0d ?? ?? ?? ?? ?? c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 ?? 01 45 0c ff 75 ?? 8d 45 f4 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MKSC_2147835431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MKSC!MTB"
        threat_id = "2147835431"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 54 24 ?? 8b ce e8}  //weight: 1, accuracy: Low
        $x_1_2 = {89 0c 24 c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 31 04 24 8b 04 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SAA_2147835787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SAA!MTB"
        threat_id = "2147835787"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 03 c6 89 45 ?? 03 55 ?? 8b 45 ?? 31 45 ?? 31 55 ?? 89 3d ?? ?? ?? ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SAB_2147838045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SAB!MTB"
        threat_id = "2147838045"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 83 25 ?? ?? ?? ?? ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SAC_2147838328_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SAC!MTB"
        threat_id = "2147838328"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 03 45 ?? 89 45 ?? 8b 45 ?? 31 45 ?? 8b 45 ?? 31 45 ?? 89 1d ?? ?? ?? ?? 8b 45 ?? 29 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SAE_2147839293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SAE!MTB"
        threat_id = "2147839293"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 0c 33 45 ?? 83 25 ?? ?? ?? ?? ?? 2b d8 89 45 ?? 8b c3 c1 e0 ?? 89 5d ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SAF_2147841314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SAF!MTB"
        threat_id = "2147841314"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 d3 e8 03 c5 89 44 24 ?? 33 44 24 ?? 31 44 24 ?? 8b 44 ?? 18 89 44 ?? 2c 8b 44 24 ?? 29 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8d 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SAH_2147841760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SAH!MTB"
        threat_id = "2147841760"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 44 24 30 01 44 24 ?? 8b 44 24 ?? c1 e8 ?? 89 44 24 ?? 8b 4c 24 ?? 8d 44 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SAI_2147841846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SAI!MTB"
        threat_id = "2147841846"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 8b 4d ?? 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 ?? 03 45 ?? 03 ce 33 c8 31 4d ?? 2b 7d ?? c7 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SAJ_2147842064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SAJ!MTB"
        threat_id = "2147842064"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e0 ?? 89 45 ?? 8b 45 ?? 01 45 ?? 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 ?? 03 45 ?? 03 de 33 d8 31 5d ?? 2b 7d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SAK_2147842220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SAK!MTB"
        threat_id = "2147842220"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 8d 4c 24 ?? e8 ?? ?? ?? ?? 01 7c 24 ?? 89 6c 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? ?? 01 44 24 ?? 8b 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 d3 e8 8b 4c 24 ?? 31 4c 24 ?? 03 c3 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MCC_2147842823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MCC!MTB"
        threat_id = "2147842823"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d6 c1 ea ?? 03 d5 89 54 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 83 ef ?? 8b 4c 24 ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SAL_2147843061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SAL!MTB"
        threat_id = "2147843061"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 89 74 24 ?? e8 ?? ?? ?? ?? 01 5c 24 ?? c7 44 24 ?? ?? ?? ?? ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 c1 e8 ?? 03 c5 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 ?? 33 4c 24 ?? 8d 44 24 ?? 89 4c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_RMA_2147843418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.RMA!MTB"
        threat_id = "2147843418"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 c1 ee ?? 03 f5 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 33 ce 8d 44 24 ?? 89 4c 24 ?? e8 ?? ?? ?? ?? 81 44 24 ?? ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SEA_2147844821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SEA!MTB"
        threat_id = "2147844821"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 c5 33 44 24 ?? 33 c8 8d 44 24 ?? 89 4c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 8b 4c 24 ?? 33 4c 24 ?? 2b f1 8b c6 8d 4c 24 ?? 89 74 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SEB_2147845080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SEB!MTB"
        threat_id = "2147845080"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 ?? 03 c5 33 44 24 ?? 33 c8 2b f9 8d 44 24 ?? 89 4c 24 ?? 89 7c 24 ?? e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85 ?? ?? ?? ?? 8b 84 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_QMQ_2147845470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.QMQ!MTB"
        threat_id = "2147845470"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 8d 4c 24 ?? e8 ?? ?? ?? ?? 01 6c 24 ?? 89 74 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? ?? 01 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 4c 24 ?? 31 4c 24 ?? 8b f3 c1 ee ?? 03 74 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 ff 15 ?? ?? ?? ?? 8b 54 24 ?? 52 56 8d 44 24 ?? 50 e8 ?? ?? ?? ?? 2b 7c 24 ?? 89 7c 24 ?? 8b 44 24 ?? 29 44 24 ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_UTY_2147846112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.UTY!MTB"
        threat_id = "2147846112"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b f9 8b d7 c1 e2 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b c7 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8d 0c 3b 31 4c 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_JKM_2147847306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.JKM!MTB"
        threat_id = "2147847306"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 44 24 28 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 c6 33 c1 2b d8 89 44 24 ?? 8b c3 c1 e0 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10 75}  //weight: 1, accuracy: Low
        $x_1_2 = {ff 15 50 10 40 00 31 74 24 10 8b 44 24 14 31 44 24 10 2b 7c 24 10 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MCZ_2147847533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MCZ!MTB"
        threat_id = "2147847533"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 c7 04 24 04 00 00 00 8b 44 24 08 83 2c 24 04 01 04 24 8b 04 24 31 01}  //weight: 1, accuracy: High
        $x_1_2 = {8b d7 c1 ea ?? 03 f7 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 44 24 ?? 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 8b 44 24 ?? 33 ce 33 c1 2b d8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MCD_2147847631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MCD!MTB"
        threat_id = "2147847631"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 c7 04 24 ?? ?? ?? ?? 8b 44 24 08 83 2c 24 04 01 04 24 8b 04 24 31 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c7 c1 e8 ?? 8d 34 2f c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8b 44 24 20 01 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 4c 24 30 51 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 54 24 ?? 8b 44 24 ?? 33 d6 33 c2 2b d8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_IZQ_2147847758_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.IZQ!MTB"
        threat_id = "2147847758"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 c7 04 24 ?? ?? ?? ?? 8b 44 24 ?? 83 2c 24 04 01 ?? 24 8b 04 24 31 01}  //weight: 1, accuracy: Low
        $x_1_2 = {8b d7 c1 ea ?? 8d 34 2f c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 18 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 8d 44 24 ?? 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 8b 4c 24 ?? 8b 44 24 ?? 33 ce 33 c1 2b d8 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_QMI_2147847831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.QMI!MTB"
        threat_id = "2147847831"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 e8 8b 4c 24 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 44 24 ?? 8d 44 24 ?? e8 ?? ?? ?? ?? 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 68 ?? ?? ?? ?? 57 57 ff 15 ?? ?? ?? ?? 8b 54 24 ?? 31 54 24 30 8b 44 24}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 ee 03 f5 8b 44 24 ?? 31 44 24 ?? 81 3d ?? ?? ?? ?? ?? ?? ?? ?? 75 ?? 57 57 57 ff 15 ?? ?? ?? ?? 31 74 24 ?? 8b 44 24 ?? 29 44 24 ?? 8d 44 24 2c e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_CSAD_2147847989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.CSAD!MTB"
        threat_id = "2147847989"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 44 24 28 57 8d 4c 24 14 89 44 24 18 c7 05 90 bc 6a 00 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 44 24 14 33 44 24 10 c7 05 90 bc 6a 00 00 00 00 00 2b f0 8b ce c1 e1 ?? 89 44 24 14 89 4c 24 10 8b 44 24 2c 01 44 24 10 8b d6 c1 ea ?? 8d 3c 33 c7 05 98 bc 6a 00 ?? ?? ?? ?? c7 05 9c bc 6a 00 ?? ?? ?? ?? 89 54 24 14 8b 44 24 24 01 44 24 14 81 3d 3c 13 6b 00 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 14 8b 44 24 10 33 cf 33 c1 2b e8 81 3d 3c 13 6b 00 ?? ?? ?? ?? 89 44 24 10 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SSH_2147848249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SSH!MTB"
        threat_id = "2147848249"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 8b 4c 24 38 8d 44 24 ?? 89 54 24 28 e8 28 fe ff ff 8b 44 24 24 31 44 24 14 81 3d 0c 02 55 02 21 01 00 00 75 ?? 53 53 53 ff 15 ?? ?? ?? ?? 8b 44 24 14 33 44 24 28 81 c7 ?? ?? ?? ?? 2b f0 83 6c 24 34 01 89 44 24 14 89 7c 24 2c 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_CRIT_2147849129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.CRIT!MTB"
        threat_id = "2147849129"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bepujob" ascii //weight: 1
        $x_1_2 = "lenazohehiro rupugegoxuzevoyakuruhiw capobigu cemuhitutihivatusocacageducayihe" ascii //weight: 1
        $x_1_3 = "bohaxavuwedu" ascii //weight: 1
        $x_1_4 = "Bagenifute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_CRIS_2147849158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.CRIS!MTB"
        threat_id = "2147849158"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 81 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_QWE_2147849317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.QWE!MTB"
        threat_id = "2147849317"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 89 54 24 ?? 8b 44 24 34 01 44 24 ?? 8b 44 24 24 31 44 ?? 10 8b 44 24 ?? 8b 4c 24 14 50 51 8d 54 24 ?? 52 e8 ?? ?? ?? ?? 8b 4c 24 10 8d 44 24 2c e8 ?? ?? ?? ?? 8d 44 24 28 e8 ?? ?? ?? ?? 83 6c 24 ?? ?? 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_CRTD_2147849619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.CRTD!MTB"
        threat_id = "2147849619"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c7 33 c1 2b f0 89 44 24 ?? 8b c6 c1 e0 ?? 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b ce c1 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MUN_2147850776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MUN!MTB"
        threat_id = "2147850776"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 c1 e8 05 03 44 24 28 03 cd 33 c1 8d 0c 3b 33 c1 2b f0 8b d6 c1 e2 04 89 44 24 14 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 54 24}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d3 33 c2 2b f8 8d 44 24 1c e8 ?? ?? ?? ?? ff 4c 24 18 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_NDD_2147851129_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.NDD!MTB"
        threat_id = "2147851129"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ee 8b 4c 24 30 8d 44 24 20 89 54 24 34 89 74 24 20 c7 05 ?? ?? ?? ?? ee 3d ea f4 e8 ?? ?? ?? ?? 8b 44 24 34 31 44 24 10 81 3d ?? ?? ?? ?? e6 09 00 00 75 0c 6a 00 6a 00 6a 00 ff 15 60 10 40 00 8b 44 24 10 31 44 24 20 81 3d ?? ?? ?? ?? 13 02 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MJQ_2147852287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MJQ!MTB"
        threat_id = "2147852287"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 ec 83 45 f8 64 29 45 f8 83 6d f8 64 8b 45 f8 8d 4d fc e8 ?? ?? ?? ?? 8b 45 e0 01 45 fc 8b 45 f8 8b 4d f0 8d 14 01 8b 4d f4 31 55 fc ff 75 fc d3 e8 03 c3 50 8d 45 fc 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MJW_2147852288_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MJW!MTB"
        threat_id = "2147852288"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 44 24 20 03 cd 33 c1 8b 4c 24 18 03 ce 33 c1 2b f8 8b d7 c1 e2 04 81 3d ?? ?? ?? ?? 8c 07 00 00 89 44 24 14 c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 10 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 4c 24 14 8b 44 24 10 33 cb 33 c1 89 44 24 ?? 2b f0 8b 44 24 24 29 44 24 18 ff 4c 24 1c 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MJJ_2147852406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MJJ!MTB"
        threat_id = "2147852406"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e8 05 03 44 24 20 03 cd 33 c1 8d 0c 33 33 c1 2b f8 8b d7 c1 e2 04 81 3d ?? ?? ?? ?? 8c 07 00 00 89 44 24 14 c7 05 ?? ?? ?? ?? 00 00 00 00 89 54 24 10 75}  //weight: 1, accuracy: Low
        $x_1_2 = {51 6a 00 ff 15 ?? ?? ?? ?? 8b 54 24 14 8b 44 24 10 33 d3 33 c2 89 44 24 10 2b f0 8d 44 24 18 e8 ?? ?? ?? ?? ff 4c 24 1c 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_FUT_2147852507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.FUT!MTB"
        threat_id = "2147852507"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 56 56 ff 15 ?? ?? ?? ?? 8b 45 f0 83 45 f8 64 29 45 f8 83 6d f8 64 8b 45 f8 8d 4d fc e8 ?? ?? ?? ?? 8b 45 dc 01 45 fc 8b 55 f8 8b 4d f4 8b c2 d3 e8 8d 34 17 81 c7 ?? ?? ?? ?? 03 45 e4 33 c6 31 45 fc 2b 5d fc ff 4d ec 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_JJA_2147853102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.JJA!MTB"
        threat_id = "2147853102"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 54 24 24 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04 81 3d ?? ?? ?? ?? 8c 07 00 00 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 10 75}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6a 00 ff 15 ?? ?? ?? ?? 33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 81 3d ?? ?? ?? ?? 93 00 00 00 75 10 68 bc 2a 40 00 8d 4c 24 74 51 ff 15 80 10 40 00 81 c5 47 86 c8 61 ff 4c 24 18 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MJO_2147853368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MJO!MTB"
        threat_id = "2147853368"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 8d 4d f8 e8 ?? ?? ?? ?? 8b 45 dc 01 45 f8 8b 4d f4 8b 45 f0 81 45 f0 47 86 c8 61 8b d7 d3 ea 03 c7 03 55 e0 33 d0 31 55 f8 8b 45 f8 29 45 ec ff 4d e4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_BHG_2147853496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.BHG!MTB"
        threat_id = "2147853496"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 dc 01 45 f8 8b 4d f0 8b 45 f4 8b d7 d3 ea 03 c7 03 55 ?? 33 d0 31 55 f8 8b 45 f8 29 45 ec 8b 45 e0 29 45 f4 ff 4d e4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MOO_2147888257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MOO!MTB"
        threat_id = "2147888257"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 c1 ea 05 03 54 24 20 03 c5 33 d1 33 d0 2b fa 8b cf c1 e1 04 81 3d ?? ?? ?? ?? 8c 07 00 00 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 10 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 f3 31 74 24 10 8b 44 24 10 29 44 24 14 81 3d 4c 1c 2e 02 93 00 00 00 75 ?? 68 ?? ?? ?? ?? 8d 44 24 78 50 ff 15 ?? ?? ?? ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_ROC_2147888458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.ROC!MTB"
        threat_id = "2147888458"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c3 8d 4d f8 e8 ?? ?? ?? ?? 8b 45 d4 01 45 f8 8b 4d f0 8b 45 f4 8b d3 d3 ea 03 c3 03 55 dc 33 d0 31 55 f8 2b 7d f8 89 7d e8 8b 45 e4 29 45 f4 ff 4d ec 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_WAQ_2147888592_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.WAQ!MTB"
        threat_id = "2147888592"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f7 d3 ee 8d 04 3b 89 45 e0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 75 e4 8b 45 e0 31 45 fc 33 75 fc 81 3d ?? ?? ?? ?? 13 02 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b c6 8d 4d fc e8 ?? ?? ?? ?? 8b 45 dc 01 45 fc 8b 4d f8 8d 04 33 31 45 fc d3 ee 03 75 d8 81 3d ?? ?? ?? ?? 21 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_CBEC_2147888785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.CBEC!MTB"
        threat_id = "2147888785"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 dc 01 45 fc 8b 4d f8 8d 04 33 31 45 fc d3 ee 03 75 d8 81 3d}  //weight: 1, accuracy: High
        $x_1_2 = {31 75 fc 2b 7d fc 81 c3 ?? ?? ?? ?? ff 4d ec 89 7d f0 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_CBED_2147888898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.CBED!MTB"
        threat_id = "2147888898"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 dc 01 45 fc 8b 4d f8 8d 04 ?? 31 45 fc d3 ?? 03 ?? ?? 81 3d}  //weight: 1, accuracy: Low
        $x_1_2 = {31 7d fc 8b 45 fc 29 45 f4 81 c3 ?? ?? ?? ?? ff 4d e8 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_LID_2147890108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.LID!MTB"
        threat_id = "2147890108"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e0 04 03 44 24 2c 8d 34 0b c1 e9 05 83 3d ?? ?? ?? ?? 1b 89 44 24 14 8b e9 75 0a ff 15 ?? ?? ?? ?? 8b 44 24 14 03 6c 24 20 c7 05 ?? ?? ?? ?? 00 00 00 00 33 ee 33 e8 2b fd 8b d7 c1 e2 04 89 54 24 14 8b 44 24 28 01 44 24 14 81 3d ?? ?? ?? ?? be 01 00 00 8d 2c 3b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MNX_2147890112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MNX!MTB"
        threat_id = "2147890112"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 c7 d3 ef 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d d4 8b 45 ec 31 45 fc 33 7d fc 81 3d ?? ?? ?? ?? 13 02 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b fb d3 ef 8b 4d e0 03 c1 33 c2 03 7d dc 81 3d ?? ?? ?? ?? 21 01 00 00 89 45 fc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_HRX_2147890425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.HRX!MTB"
        threat_id = "2147890425"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 14 18 8b c3 d3 e8 8b 4d fc 03 cf 03 45 dc 33 c1 33 c2 29 45 f0 89 45 fc 8d 45 f4 e8 ?? ?? ?? ?? ff 4d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_LAT_2147890503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.LAT!MTB"
        threat_id = "2147890503"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 14 30 8b c6 8b 75 d4 d3 e8 8b 4d fc 03 ce 03 45 ?? 33 c1 33 c2 29 45 f0 89 45 fc 8b 45 dc 29 45 f8 ff 4d e4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_JAB_2147891164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.JAB!MTB"
        threat_id = "2147891164"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c2 8d 4d fc e8 ?? ?? ?? ?? 8b 4d f8 8b 45 f0 8b 7d e0 d3 e8 8b 4d fc 03 cf 03 d3 03 45 dc 81 c3 47 86 c8 61 33 c1 33 c2 29 45 f4 ff 4d e8 89 45 fc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_JJB_2147891558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.JJB!MTB"
        threat_id = "2147891558"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 c1 e0 04 03 44 24 28 03 f9 c1 e9 05 83 3d ?? ?? ?? ?? 1b 89 44 24 10 8b d9 75 0e 6a 00 6a 00 ff 15 ?? ?? ?? ?? 8b 44 24 10 03 dd 33 df 33 d8 2b f3 8b c6}  //weight: 1, accuracy: Low
        $x_1_2 = {8b ce c1 e9 05 03 4c 24 24 c7 05 ?? ?? ?? ?? 19 36 6b ff 33 cf 31 4c 24 10 c7 05 ?? ?? ?? ?? ff ff ff ff 8b 44 24 10 29 44 24 18 8b 44 24 2c 29 44 24 14 ff 4c 24 1c 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_NAN_2147891882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.NAN!MTB"
        threat_id = "2147891882"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 dc 01 45 fc 8b 45 f8 8d 0c 03 89 4d f0 8b 4d f4 d3 e8 03 45 d4 8b c8 8b 45 f0 31 45 fc 31 4d fc 2b 7d fc 81 c3 47 86 c8 61 ff 4d e4 89 7d ec 0f 85 c1 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_GON_2147892340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.GON!MTB"
        threat_id = "2147892340"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d0 8b c8 c1 ea 05 03 54 24 20 c1 e1 04 03 4c 24 24 03 c3 33 d1 33 d0 2b f2 8b ce c1 e1 04 c7 05 ?? ?? ?? ?? 00 00 00 00 89 4c 24 10 8b 44 24 28 01 44 24 10 81 3d ?? ?? ?? ?? be 01 00 00 8d 3c 33 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_MLA_2147893742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.MLA!MTB"
        threat_id = "2147893742"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 d3 ea 8d 04 3b 89 45 f0 c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 e4 8b 45 f0 31 45 fc 33 55 fc 81 3d ?? ?? ?? ?? 13 02 00 00 89 55 f0 75}  //weight: 1, accuracy: Low
        $x_1_2 = {c1 e0 04 89 45 fc 8b 45 dc 01 45 fc 8b 55 f4 8b 4d f8 8b c2 d3 e8 8d 3c 13 81 c3 ?? ?? ?? ?? 03 45 e0 33 c7 31 45 fc 8b 45 fc 29 45 ec ff 4d e8 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_KS_2147895076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.KS!MTB"
        threat_id = "2147895076"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 44 24 18 89 44 24 18 8b 44 24 18 89 44 24 18 8b 44 24 18 29 44 24 14}  //weight: 1, accuracy: High
        $x_1_2 = {31 5c 24 10 8b 44 24 18 31 44 24 10 2b 74 24 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_GHE_2147895255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.GHE!MTB"
        threat_id = "2147895255"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c1 89 54 24 18 89 44 24 10 89 1d ?? ?? ?? ?? 8b 44 24 18 01 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 54 24 28 89 5c 24 18 8b 44 24 28 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 44 24 18}  //weight: 1, accuracy: Low
        $x_1_2 = {31 5c 24 10 8b 44 24 18 31 44 24 10 a1 ?? ?? ?? ?? 2b 74 24 10 3d 93 00 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_ZTQ_2147896798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.ZTQ!MTB"
        threat_id = "2147896798"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 8b d0 c1 ea 05 03 54 24 30 8b c8 c1 e1 04 89 54 24 1c 03 cd 8d 14 06 33 ca 89 4c 24 10 89 3d ?? ?? ?? ?? 8b 44 24 1c 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 34 89 7c 24 1c 8b 44 24 34 01 44 24 1c 8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 4c 24 1c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_IDL_2147898247_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.IDL!MTB"
        threat_id = "2147898247"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 ff 89 74 24 1c 89 3d ?? ?? ?? ?? 8b 44 24 1c 01 05 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 44 24 2c 89 7c 24 1c 8b 44 24 2c 01 44 24 1c 8b 44 24 14 33 44 24 1c 89 44 24 1c 8b 4c 24 1c}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c6 89 44 24 14 8b 44 24 1c 31 44 24 14 a1 ?? ?? ?? ?? 2b 5c 24 14 3d 93 00 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_HAB_2147900650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.HAB!MTB"
        threat_id = "2147900650"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d7 d3 ea c7 05 ?? ?? ?? ?? ee 3d ea f4 03 55 d8 8b 45 ec 31 45 fc 33 55 fc 89 55 d4 8b 45 d4 83 45 f8 64 29 45 f8 83 6d f8 64 8b 45 f8}  //weight: 1, accuracy: Low
        $x_1_2 = {01 45 f0 8b 45 f0 89 45 ec 8b 4d f4 8b 75 f8 d3 ee 8b 4d ec 31 4d fc 03 75 cc 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_STP_2147901593_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.STP!MTB"
        threat_id = "2147901593"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {d3 ea 03 d3 8b 45 ec 31 45 fc 31 55 fc 2b 7d fc 81 45 e8 ?? ?? ?? ?? ff 4d dc 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SHZ_2147902198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SHZ!MTB"
        threat_id = "2147902198"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f3 d3 ee 03 c3 89 45 e4 03 75 dc 8b 45 e4 31 45 fc 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {31 75 fc 8b 45 fc 29 45 ec 8b 45 d4 29 45 ?? ff 4d e0 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_OTG_2147902858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.OTG!MTB"
        threat_id = "2147902858"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 c1 e0 04 89 45 fc 8b 45 d8 01 45 fc 8b 4d f4 8d 04 33 89 45 e8 8b c6 d3 e8 03 45 d4 89 45 f8 8b 45 e8 31 45 fc 81 3d ?? ?? ?? ?? 03 0b 00 00 75}  //weight: 1, accuracy: Low
        $x_1_2 = {33 45 f8 81 c3 ?? ?? ?? ?? 2b f8 ff 4d e4 89 45 fc 89 7d ec 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_CCIA_2147905894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.CCIA!MTB"
        threat_id = "2147905894"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 54 24 14 8b 4c 24 10 30 04 0a 83 bc 24 24}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_CSK_2147907066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.CSK!MTB"
        threat_id = "2147907066"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c6 8b 55 fc d3 e8 03 45 d0 89 45 f0 89 45 f4 8d 04 37 33 d0 81 3d ?? ?? ?? ?? 03 0b 00 00 89 55 fc 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_RP_2147908230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.RP!MTB"
        threat_id = "2147908230"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 00 00 cc cc cc cc cc 56 8b f1 c7 06 ?? c1 40 00 e8 ?? 01 00 00 f6 44 24 08 01 74 09 56 e8 ?? 03 00 00 83 c4 04 8b c6 5e c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_SIN_2147909732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.SIN!MTB"
        threat_id = "2147909732"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 f8 8b 4d fc 33 4d f4 8b 45 f8 03 45 d8 33 c1 89 4d ?? 8b 0d 80 51 a7 01 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f8 81 f9 13 02 00 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_COF_2147909837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.COF!MTB"
        threat_id = "2147909837"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 f8 8b 4d fc 33 4d f0 8b 45 f8 03 45 dc 33 c1 89 4d fc 8b 0d ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 f8 81 f9 13 02 00 00 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_YAL_2147909868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.YAL!MTB"
        threat_id = "2147909868"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 44 24 18 e8 6b ff ff ff 8b 44 24 18 83 c0 ?? 89 44 24 10 83 6c 24 10 64 8a 4c 24 10 8b 44 24 14 30 0c 30 83 bc 24 5c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_AAX_2147910655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.AAX!MTB"
        threat_id = "2147910655"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 f8 8b 4d fc 8b 45 f8 33 4d f0 03 45 cc 33 c1 c7 05 ?? ?? ?? ?? ee 3d ea f4 81 3d ?? ?? ?? ?? 13 02 00 00 89 4d fc 89 45 f8 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_ERR_2147910914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.ERR!MTB"
        threat_id = "2147910914"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c7 d3 e8 89 45 f4 8b 45 d4 01 45 f4 8b 45 fc 33 45 e4 81 3d ?? ?? ?? ?? 03 0b 00 00 89 45 fc 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_NTE_2147911373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.NTE!MTB"
        threat_id = "2147911373"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 45 f4 83 c0 ?? 89 45 f8 83 6d f8 64 8a 4d f8 30 0c 1e 83 ff 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_RV_2147911409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.RV!MTB"
        threat_id = "2147911409"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 83 c0 ?? 89 45 ?? 83 6d ?? ?? 8a 4d ?? 30 0c 1e 83 ff ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_VID_2147911632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.VID!MTB"
        threat_id = "2147911632"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 04 8b 45 c0 83 c0 64 89 45 ?? 83 6d c4 64 8a 4d c4 30 0c 33 83 ff 0f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_TOQ_2147916216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.TOQ!MTB"
        threat_id = "2147916216"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 05 89 45 70 8b 45 70 03 85 14 ff ff ff 8d 14 33 33 c2 33 c1 2b f8 8b c7 c1 e8 05 c7 05 ?? ?? ?? ?? ee 3d ea f4 89 45 70 8b 85 10 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_StopCrypt_ASC_2147929906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/StopCrypt.ASC!MTB"
        threat_id = "2147929906"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "StopCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q" wide //weight: 3
        $x_2_2 = "Decryptfiles.txt" ascii //weight: 2
        $x_5_3 = "boot.inidesktop.inintuser.daticoncache.dbbootsect.bakntuser.dat.logBootfont.binDecryptfiles.txt" ascii //weight: 5
        $x_4_4 = "edfr789@tutanota.com" ascii //weight: 4
        $x_1_5 = "we advise you contact us in less than 72 hours, otherwise there is a possibility that your files will never be returned" ascii //weight: 1
        $x_1_6 = "Do not try to recover your files without a decrypt tool, you may damage them making them impossible to recover" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

