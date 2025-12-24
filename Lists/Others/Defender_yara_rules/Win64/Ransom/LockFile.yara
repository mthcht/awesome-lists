rule Ransom_Win64_LockFile_MBK_2147795409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.MBK!MTB"
        threat_id = "2147795409"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "winsta0\\default" ascii //weight: 1
        $x_1_2 = "YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_3 = "The price of decryption software is" ascii //weight: 1
        $x_1_4 = "We only accept Bitcoin payment" ascii //weight: 1
        $x_1_5 = {52 00 45 00 41 00 44 00 4d 00 45 00 2d 00 46 00 49 00 4c 00 45 00 [0-32] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_6 = {52 45 41 44 4d 45 2d 46 49 4c 45 [0-32] 2e 68 74 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win64_LockFile_A_2147925023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.A!MTB"
        threat_id = "2147925023"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "encryptdecrypt" ascii //weight: 1
        $x_1_2 = ".rustsomware" ascii //weight: 1
        $x_1_3 = " pay " ascii //weight: 1
        $x_1_4 = "/rustc/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockFile_B_2147925024_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.B!MTB"
        threat_id = "2147925024"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 ff c8 48 89 44 24 58 45 8b 2c 0e 41 8b 5c 0e 04 41 0f cd 44 33 ac 24 00 01 00 00 0f cb 33 9c 24 f8 00 00 00 41 8b 6c 0e 08 0f cd 33 ac 24 f0 00 00 00 48 89 8c 24 08 01 00 00 41 8b 74 0e 0c 0f ce 33 b4 24 28 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockFile_C_2147925124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.C!MTB"
        threat_id = "2147925124"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " pay " ascii //weight: 1
        $x_1_2 = "/rustc/" ascii //weight: 1
        $x_1_3 = "decrypt" ascii //weight: 1
        $x_1_4 = "pinglocalhost-n1>nul&&del/C" ascii //weight: 1
        $x_1_5 = "library\\core\\src\\escape.rs" ascii //weight: 1
        $x_1_6 = "readme.txt" ascii //weight: 1
        $x_1_7 = "encrypt" ascii //weight: 1
        $x_1_8 = "download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockFile_D_2147925127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.D!MTB"
        threat_id = "2147925127"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 21 48 8b 85 f8 06 00 00 8b 08 ba 6b 6e 69 67 31 d1 0f b7 40 04 35 68 74 00 00 09 c8}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 85 e0 07 00 00 0f b6 8d e8 07 00 00 88 8d 56 08 00 00 48 89 85 f8 07 00 00 48 8d 48 10}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 44 24 20 48 c7 44 24 40 00 00 00 00 48 89 f9 31 d2 45 31 c0 45 31 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockFile_E_2147925380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.E!MTB"
        threat_id = "2147925380"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_2 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_3 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_4 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_5 = ".encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockFile_DA_2147925384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.DA!MTB"
        threat_id = "2147925384"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "deleteshadows/quiet" ascii //weight: 1
        $x_1_2 = "Your personal decryption code:" ascii //weight: 1
        $x_1_3 = "your files are permanently deleted" ascii //weight: 1
        $x_1_4 = {54 00 6f 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 00 73 00 2c 00 20 00 73 00 65 00 6e 00 64 00 [0-15] 42 00 54 00 43 00}  //weight: 1, accuracy: Low
        $x_1_5 = {54 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 73 65 6e 64 [0-15] 42 54 43}  //weight: 1, accuracy: Low
        $x_1_6 = "Your files have been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win64_LockFile_DB_2147925385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.DB!MTB"
        threat_id = "2147925385"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmdnetconfigstart=disabledFailed to wipe" ascii //weight: 1
        $x_1_2 = "Windows Update system corrupted successfully" ascii //weight: 1
        $x_1_3 = "/home/medusa/" ascii //weight: 1
        $x_1_4 = "cmd.exe /e:ON /v:OFF /d /c" ascii //weight: 1
        $x_1_5 = "Once instance has previously been poisoned" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockFile_MKV_2147947763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.MKV!MTB"
        threat_id = "2147947763"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 8b 0b 33 d2 49 8b c0 48 f7 73 10 0f b6 0c 0a 48 8d 45 e7 48 83 7d ?? 0f 48 0f 47 45 e7 42 30 0c 00 49 ff c0 4c 3b 45 f7 72}  //weight: 5, accuracy: Low
        $x_1_2 = "YOUR SYSTEM IS LOCKED!" ascii //weight: 1
        $x_1_3 = "vssadmin delete shadows /all /quiet" ascii //weight: 1
        $x_1_4 = "DECRYPT_OR_LOSE_EVERYTHING" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockFile_NIT_2147952287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.NIT!MTB"
        threat_id = "2147952287"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 5c 24 30 48 8d 4d fc 48 89 4c 24 28 48 89 54 24 20 41 b9 00 00 00 00 41 b8 01 00 00 00 ba 00 00 00 00 48 89 c1 48 8b 05 11 ?? 13 00 ff d0 85 c0 0f 94 c0 84 c0}  //weight: 2, accuracy: Low
        $x_1_2 = {c7 44 24 60 01 00 10 00 ff 15 6e ?? 11 00 31 d2 48 8b 4e 28 ff 15 aa ?? 11 00 3d 02 01 00 00 0f 85 f4 fe ff ff 48 8b 4e 28 48 8d 54 24 30 ff 15 40 ?? 11 00 48 8d 05 81 fa ff ff 48 8b 4e 28 48 8d 54 24 30 48 89 84 24 28 01 00 00 ff 15 0a ?? 11 00 0f b6 46 40 83 66 44 fe 83 e0 f0 83 c8 05 88 46 40 f0 83 05 c1 0e 11 00 01 48 8b 4e 30 48 85 c9 74 06 ff 15 ba ?? 11 00 48 8d 4e 38 e8 49 d6 ff ff 48 8b 4e 28 ff 15 77 ?? 11 00 e9 87 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockFile_NIT_2147952287_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.NIT!MTB"
        threat_id = "2147952287"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8d 25 7f ?? 00 00 4c 89 a4 24 b0 03 00 00 48 8d 05 88 ?? 00 00 48 89 84 24 b8 03 00 00 48 89 bc 24 c0 03 00 00 33 d2 b9 02 00 00 00 ff 15 cb ?? 00 00 4c 8b f0 c7 84 24 70 01 00 00 ?? ?? 00 00 33 d2 41 b8 34 02 00 00 48 8d 8c 24 74 01 00 00 e8 60 8c 00 00 48 8d 94 24 70 01 00 00 49 8b ce ff 15 1f ?? 00 00 85 c0}  //weight: 2, accuracy: Low
        $x_2_2 = "vssadmin delete shadows /all /quiet" ascii //weight: 2
        $x_2_3 = "bcdedit /set {default} recoveryenabled No" ascii //weight: 2
        $x_2_4 = "net stop WinDefend" ascii //weight: 2
        $x_2_5 = "netsh advfirewall set allprofiles state off" ascii //weight: 2
        $x_5_6 = "All files on drives" ascii //weight: 5
        $x_5_7 = "are ENCRYPTED" ascii //weight: 5
        $x_2_8 = "Bitcoin" ascii //weight: 2
        $x_2_9 = "decrypt your files" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 6 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win64_LockFile_ARA_2147956833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.ARA!MTB"
        threat_id = "2147956833"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 2
        $x_1_2 = "encrypted" ascii //weight: 1
        $x_1_3 = "ransomware" ascii //weight: 1
        $x_1_4 = "Bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockFile_NP_2147958500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.NP!AMTB"
        threat_id = "2147958500"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rson.pdb" ascii //weight: 1
        $x_1_2 = "TIME EXPIRED! Your files will be permanently deleted!" ascii //weight: 1
        $x_1_3 = "Payment Status - NOT PAID" ascii //weight: 1
        $x_1_4 = "It may cause permanent file corruption!" ascii //weight: 1
        $x_1_5 = "WannaCryReplica" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_LockFile_ARR_2147960058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/LockFile.ARR!MTB"
        threat_id = "2147960058"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "LockFile"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 8a 04 0a 44 30 04 0f 4c 8d 41 ?? 4c 89 c1 4c 39 c3}  //weight: 10, accuracy: Low
        $x_9_2 = {66 41 0f fe d4 66 44 0f ef eb 66 0f ef f1 66 41 0f ef fe 66 45 0f 6f fe 66 0f ef c2 66 45 0f 6f f5}  //weight: 9, accuracy: High
        $x_1_3 = "YOUR FILES HAVE BEEN ENCRYPTED!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

