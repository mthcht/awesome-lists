rule Ransom_Win32_Lockbit_SA_2147750588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lockbit.SA!MSR"
        threat_id = "2147750588"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShutdownBlockReasonCreate" ascii //weight: 1
        $x_2_2 = "LockBit Ransom" ascii //weight: 2
        $x_2_3 = "http://lockbitks2tvnmwk.onion" ascii //weight: 2
        $x_1_4 = "encrypted files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Lockbit_AA_2147785223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lockbit.AA!MTB"
        threat_id = "2147785223"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LockBit Ransomware" ascii //weight: 1
        $x_1_2 = "All your files stolen and encrypted" wide //weight: 1
        $x_1_3 = ".lock" wide //weight: 1
        $x_1_4 = "Lockbit\\shell\\Open\\Command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Lockbit_SB_2147787086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lockbit.SB"
        threat_id = "2147787086"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "LockBit_2_0_Ransom" wide //weight: 10
        $x_10_2 = {59 00 6f 00 75 00 20 00 63 00 61 00 6e 00 20 00 63 00 6f 00 6d 00 6d 00 75 00 6e 00 69 00 63 00 61 00 74 00 65 00 20 00 77 00 69 00 74 00 68 00 20 00 75 00 73 00 20 00 74 00 68 00 72 00 6f 00 75 00 67 00 68 00 20 00 74 00 68 00 65 00 20 00 54 00 6f 00 78 00 20 00 6d 00 65 00 73 00 73 00 65 00 6e 00 67 00 65 00 72 00 [0-6] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 74 00 6f 00 78 00 2e 00 63 00 68 00 61 00 74 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 68 00 74 00 6d 00 6c 00}  //weight: 10, accuracy: Low
        $x_10_3 = {2e 00 6f 00 6e 00 69 00 6f 00 6e 00 [0-96] 25 00 73 00 2e 00 62 00 6d 00 70 00}  //weight: 10, accuracy: Low
        $x_10_4 = {47 c6 84 24 ?? 00 00 00 44 c6 84 24 ?? 00 00 00 49 c6 84 24 ?? 00 00 00 50 c6 84 24 ?? 00 00 00 4c c6 84 24 ?? 00 00 00 55 c6 84 24 ?? 00 00 00 53 c6 84 24 ?? 00 00 00 0e c6 84 24 ?? 00 00 00 44 c6 84 24 ?? 00 00 00 4c c6 84 24 ?? 00 00 00 4c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Lockbit_HA_2147844400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lockbit.HA!MTB"
        threat_id = "2147844400"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 5a 01 66 c7 42 05 c1 c0 88 4a 07 c6 42 08 35 89 42 09 66 c7 42 0d ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Lockbit_AC_2147845570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lockbit.AC!MTB"
        threat_id = "2147845570"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 7f 8b cb 5e 8a 84 ?? 69 ff ff ff 0f b6 c0 83 e8 ?? 6b c0 ?? 99 f7 fe 8d 04 16 99 f7 fe 88 94 0d 69 ff ff ff 41 83 f9 16 8a 84 ?? 69 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 7f 8b f3 5f 8a 84 ?? 69 ff ff ff 0f b6 c0 6a ?? 59 2b c8 6b c1 ?? 99 f7 ff 8d 04 17 99 f7 ff 88 94 ?? 69 ff ff ff 46 83 fe 16 8a 84 ?? 69 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_Win32_Lockbit_RPA_2147849412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lockbit.RPA!MTB"
        threat_id = "2147849412"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 54 0d 00 02 d3 8a 5c 15 00 8a 54 1d 00 8a 54 15 00 fe c2 8a 44 15 00 30 07 8a 54 1d 00 86 54 0d 00 88 54 1d 00 fe c1 47 4e 85 f6 75 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Lockbit_AK_2147897364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lockbit.AK!ibt"
        threat_id = "2147897364"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 40 10 64 8b 00 8b 40 0c 8d 48 0c 89 4d f8 8b 48 0c 8b 59 18 33 c0 40 c1 e0 05 8d 40 1d 8b 44 03 ff 8d 04 03 8b 50 78 85 d2}  //weight: 1, accuracy: High
        $x_1_2 = {6a 00 6a 00 6a 00 6a 00 6a 00 68 02 10 04 00 ff d0 8b f0 85 f6 0f 84 7c 01 00 00 8b 40 40 c1 e8 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Lockbit_DY_2147909067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lockbit.DY!MTB"
        threat_id = "2147909067"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 44 1d f8 30 04 3e 8d 45 f8 50 43 e8 ?? ?? ?? ?? 59 3b d8 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Lockbit_SS_2147909068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lockbit.SS!MTB"
        threat_id = "2147909068"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InternetReadFile" ascii //weight: 1
        $x_1_2 = {68 74 74 70 3a 2f 2f 31 39 33 2e 32 33 33 2e 31 33 32 2e 31 37 37 2f [0-15] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "ShellExecuteW" ascii //weight: 1
        $x_1_4 = "InternetOpenUrlW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Lockbit_NIT_2147932224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lockbit.NIT!MTB"
        threat_id = "2147932224"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lockbit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 54 30 02 8b 0c fb 8b c1 c1 e8 18 88 46 fe 8b c1 c1 e8 10 88 46 ff 8b c1 c1 e8 08 88 06 8b c2 c1 e8 18 8d 76 08 88 46 fa 8b c2 c1 e8 10 88 46 fb 8b c2 c1 e8 08 47 88 46 fc 8b 45 fc 88 4e f9 88 56 fd 83 ff 08}  //weight: 2, accuracy: High
        $x_1_2 = {4a 8d 76 fc 8b 46 04 85 d2 7e 04 8b 0e eb 02 8b cf c1 e9 1d c1 e0 03 0b c8 89 4c 95 e8 85 d2 75 df}  //weight: 1, accuracy: High
        $x_1_3 = "Tor Browser" ascii //weight: 1
        $x_1_4 = "data is completely encrypted" ascii //weight: 1
        $x_1_5 = "decryption keys" ascii //weight: 1
        $x_1_6 = "Reyonpharm_hacked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

