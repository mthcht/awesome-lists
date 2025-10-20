rule VirTool_Win32_Bruterat_A_2147825897_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bruterat.A"
        threat_id = "2147825897"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bruterat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "] %s Password History:" ascii //weight: 1
        $x_1_2 = "] SAM Username:" ascii //weight: 1
        $x_1_3 = "CrackNames: 0x" ascii //weight: 1
        $x_1_4 = "] Syncing DC:" ascii //weight: 1
        $x_1_5 = "] User has Admin privileges" ascii //weight: 1
        $x_1_6 = "] Spoofed argument:" ascii //weight: 1
        $x_1_7 = "] Token Ring adapter" ascii //weight: 1
        $x_1_8 = "] Active Routes:" ascii //weight: 1
        $x_1_9 = "] Impersonated:" ascii //weight: 1
        $x_1_10 = "] Crisis Monitor:" ascii //weight: 1
        $x_1_11 = "] Running dotnet_v%lu" ascii //weight: 1
        $x_1_12 = "] Screenshot downloaded:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Bruterat_B_2147829342_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bruterat.B"
        threat_id = "2147829342"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bruterat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 ca af 91}  //weight: 1, accuracy: High
        $x_1_2 = {a1 6a 3d d8}  //weight: 1, accuracy: High
        $x_1_3 = {94 9b 15 d5}  //weight: 1, accuracy: High
        $x_1_4 = {b6 19 18 e7}  //weight: 1, accuracy: High
        $x_1_5 = {a4 19 70 e9}  //weight: 1, accuracy: High
        $x_1_6 = "] Elevated" ascii //weight: 1
        $x_1_7 = "] Injected" ascii //weight: 1
        $x_1_8 = "] Spoofed" ascii //weight: 1
        $x_1_9 = "] TCP listener started" ascii //weight: 1
        $x_1_10 = "] Account Lockout Policy" ascii //weight: 1
        $x_1_11 = "] User has Admin privilege" ascii //weight: 1
        $x_1_12 = "] Screenshot downloaded:" ascii //weight: 1
        $x_1_13 = "] Impersonated" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule VirTool_Win32_Bruterat_B_2147829342_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bruterat.B"
        threat_id = "2147829342"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bruterat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {54 ca af 91}  //weight: 1, accuracy: High
        $x_1_2 = {a1 6a 3d d8}  //weight: 1, accuracy: High
        $x_1_3 = {94 9b 15 d5}  //weight: 1, accuracy: High
        $x_1_4 = {b6 19 18 e7}  //weight: 1, accuracy: High
        $x_1_5 = {a4 19 70 e9}  //weight: 1, accuracy: High
        $x_1_6 = "] SAM Username:" ascii //weight: 1
        $x_1_7 = "] User is privileged" ascii //weight: 1
        $x_1_8 = "] Alertable thread:" ascii //weight: 1
        $x_1_9 = "] Elevated Privilege" ascii //weight: 1
        $x_1_10 = "] Screenshot downloaded:" ascii //weight: 1
        $x_1_11 = "] Impersonated" ascii //weight: 1
        $x_1_12 = "] AMSI patched" ascii //weight: 1
        $x_1_13 = "] Syncing DC:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule VirTool_Win32_Bruterat_2147832604_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bruterat!svc"
        threat_id = "2147832604"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bruterat"
        severity = "Critical"
        info = "svc: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\",\"uid\":\"" wide //weight: 1
        $x_1_2 = "\",\"pid\":\"" wide //weight: 1
        $x_1_3 = {22 00 2c 00 22 00 61 00 72 00 63 00 68 00 22 00 3a 00 22 00 78 00 [0-8] 22 00 2c 00 22 00 62 00 6c 00 64 00 22 00 3a 00 22 00}  //weight: 1, accuracy: Low
        $x_1_4 = "{\"cds\":{\"auth\":\"" wide //weight: 1
        $x_1_5 = "\"},\"mtdt\":{\"h_name\":\"" wide //weight: 1
        $x_1_6 = "\",\"p_name\":\"" wide //weight: 1
        $x_1_7 = "\"},\"dt\":{\"chkin\":\"" wide //weight: 1
        $x_1_8 = "\",\"dfname\":\"" wide //weight: 1
        $x_1_9 = "\",\"dfsize\":\"" wide //weight: 1
        $x_1_10 = "\",\"tid\":\"" wide //weight: 1
        $x_1_11 = "\",\"s4a\":\"" wide //weight: 1
        $x_1_12 = "\",\"wver\":\"" wide //weight: 1
        $x_1_13 = {22 00 2c 00 22 00 77 00 76 00 65 00 72 00 22 00 3a 00 22 00 [0-16] 22 00 2c 00 22 00 62 00 6c 00 64 00 22 00 3a 00 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule VirTool_Win32_Bruterat_SD_2147834560_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bruterat.SD"
        threat_id = "2147834560"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bruterat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 00 00 00 00 41 5f 55 50 53 51 52 56 57 41 50 41 51 41 52 41 53 41 54 41 55 41 56 41 57 48 89 e5 48 83 e4 f0}  //weight: 1, accuracy: High
        $x_1_2 = {41 5f 41 5e 41 5d 41 5c 41 5b 41 5a 41 59 41 58 5f 5e 5a 59 5b 58 5d c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Bruterat_D_2147893558_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bruterat.D"
        threat_id = "2147893558"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bruterat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 50 3c 8d 4a c0 81 f9 bf 03 00 00 77 e8 81 3c 10 ?? ?? 00 00 75 df}  //weight: 1, accuracy: Low
        $x_1_2 = {83 e8 01 66 81 38 4d 5a 75 f6 8b 50 ?? 8d 4a c0 81 f9 bf 03 00 00 77 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Bruterat_B_2147954592_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bruterat.B!svc"
        threat_id = "2147954592"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bruterat"
        severity = "Critical"
        info = "svc: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 7f 04 4b 53 53 4d 0f 85}  //weight: 1, accuracy: High
        $x_1_2 = {80 79 ff cc 74 58 45 85 c0 75 04 48 83 e9 20 44 8a 41 03 44 8a 09 41 80 f8 e9 74 06 41 80 f9 e9 75 07 ff c2 45 31 c0 eb d7}  //weight: 1, accuracy: High
        $x_1_3 = {31 c0 41 80 f9 4c 75 2f 80 79 01 8b 75 29 80 79 02 d1 75 21 41 80 f8 b8 75 1b 80 79 06 00 75 17 0f b6 41 05 c1 e0 08 41 89 c0 0f b6 41 04 44 09 c0 01 d0 eb 02 31 c0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win32_Bruterat_B_2147954592_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bruterat.B!svc"
        threat_id = "2147954592"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bruterat"
        severity = "Critical"
        info = "svc: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 79 ff cc 74 58 45 85 c0 75 04 48 83 e9 20 44 8a 41 03 44 8a 09 41 80 f8 e9 74 06 41 80 f9 e9 75 07 ff c2 45 31 c0 eb d7}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 41 80 f9 4c 75 2f 80 79 01 8b 75 29 80 79 02 d1 75 21 41 80 f8 b8 75 1b 80 79 06 00 75 17 0f b6 41 05 c1 e0 08 41 89 c0 0f b6 41 04 44 09 c0 01 d0 eb 02 31 c0 c3}  //weight: 1, accuracy: High
        $x_1_3 = {ba 08 00 00 00 48 83 c9 ff 45 31 e4 48 b8 53 65 44 65 62 75 67 50 48 89 44 24 3b 4c 8d 44 24 28 48 b8 72 69 76 69 6c 65 67 65 c6 44 24 4b 00 48 89 44 24 43 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

