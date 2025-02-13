rule Trojan_Win64_Shelm_MB_2147838779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.MB!MTB"
        threat_id = "2147838779"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 86 49 eb 67 31 5d f2 69 1a 5c 3c b9 1b e0 1e 18 53 97 88 55 90 fa 8d 37 cc 99 50 9a 46 a6 74}  //weight: 5, accuracy: High
        $x_5_2 = {a1 23 f2 e2 e7 d5 42 0d b9 40 bf ab 85 2b 97 42 e7 33 cf 70 3b df 39 f2 7e c5 86 54 f1 e6 9c 65}  //weight: 5, accuracy: High
        $x_1_3 = ".tls" ascii //weight: 1
        $x_1_4 = "GetStartupInfoA" ascii //weight: 1
        $x_1_5 = "SetUnhandledExceptionFilter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_MC_2147840703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.MC!MTB"
        threat_id = "2147840703"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "yxsohezazveqzwx.dll" ascii //weight: 5
        $x_1_2 = "DllInstall" ascii //weight: 1
        $x_1_3 = "DllMain" ascii //weight: 1
        $x_1_4 = "DllRegisterServer" ascii //weight: 1
        $x_1_5 = "DllUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_MD_2147842167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.MD!MTB"
        threat_id = "2147842167"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "lsztjuwljkjnvyjroqeqsyqddstrbrue" ascii //weight: 5
        $x_2_2 = "jnnfcoy.cpl" ascii //weight: 2
        $x_2_3 = "NimMain" ascii //weight: 2
        $x_1_4 = "DllInstall" ascii //weight: 1
        $x_1_5 = "DllMain" ascii //weight: 1
        $x_1_6 = "DllRegisterServer" ascii //weight: 1
        $x_1_7 = "DllUnregisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_MKV_2147846780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.MKV!MTB"
        threat_id = "2147846780"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 d8 31 d2 48 f7 f6 41 8a 04 1f 48 8b 8d a8 0f 00 00 32 04 11 4c 89 f1 89 c2 e8 ef 72 ff ff 48 89 fb eb c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_ABS_2147851293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.ABS!MTB"
        threat_id = "2147851293"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 0f b6 04 10 32 45 fb 89 c1 8b 45 fc 48 98 48 8d 15 ?? ?? ?? ?? 88 0c 10 83 45 fc 01 8b 45 fc 3d ?? ?? ?? ?? ?? ?? 41 b9 40 00 00 00 41 b8 00 10 00 00 ba ?? ?? ?? ?? b9 00 00 00 00 48 8b 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_RC_2147851541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.RC!MTB"
        threat_id = "2147851541"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 98 48 8d 15 ?? ?? ?? ?? 0f b6 04 10 83 f0 45 89 c1 8b 85 8c 00 00 00 48 98 48 8d 15 ?? ?? ?? ?? 88 0c 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_RC_2147851541_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.RC!MTB"
        threat_id = "2147851541"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 4c 8b 44 24 ?? 49 8b c0 41 b8 04 00 00 00 49 f7 f0 48 8b c2 0f be 44 04 ?? 48 8b 54 24 ?? 0f b6 0c 11 33 c8 8b c1 48 63 4c 24 ?? 48 8d 15 ?? ?? ?? ?? 88 04 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_B_2147851568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.B!MTB"
        threat_id = "2147851568"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 ec 28 48 8d 0d e5 11 00 00 e8 90}  //weight: 2, accuracy: High
        $x_2_2 = {ff 33 c9 ba ?? ?? ?? ?? 41 b8 00 10 00 00 44 8d 49 40 ff 15 69 0f 00 00 48 8d 0d ?? ?? ?? ?? 41 b8 ?? ?? ?? ?? 4c 8b c8 48 8b d0 66}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_C_2147851577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.C!MTB"
        threat_id = "2147851577"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {40 53 48 83 ec 30 0f 29 74 24 20 ff 15 ?? ?? ?? ?? 48 8b c8 33 d2 ff 15 ?? ?? ?? ?? 66 0f 6f 35 ?? ?? 00 00 33 c9 ba ?? ?? ?? ?? 41 b8 00 10 00 00 44 8d 49 40 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 75 ?? 48 8d 0d 26 12 00 00 ff 15 ?? ?? ?? ?? 8d 43 01 0f 28 74 24 20 48 83 c4 30}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_D_2147851584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.D!MTB"
        threat_id = "2147851584"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b 44 24 48 48 8d 44 24 50 48 8b 4c 24 40 45 33 c9 ba 10 66 00 00 48 89 44 24 20 ff 15 ?? ?? 00 00 85 c0 74 ?? 48 8b 4c 24 50 48 8d 44 24 30 48 89 44 24 28 45 33 c9 48 8d 85 70 03 00 00 45 33 c0 33 d2 48 89 44 24 20 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_E_2147851952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.E!MTB"
        threat_id = "2147851952"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 04 39 85 b4 03 00 00 7d ?? 48 63 85 b4 03 00 00 0f b6 44 05 70 83 f0 ?? 48 63 8d b4 03 00 00 88 44 0d 70 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_F_2147851964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.F!MTB"
        threat_id = "2147851964"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Shell code at %p" ascii //weight: 2
        $x_2_2 = "My shellcode pointer %p" ascii //weight: 2
        $x_2_3 = "Thread created at" ascii //weight: 2
        $x_2_4 = "dll_path [process_name]" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_G_2147851978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.G!MTB"
        threat_id = "2147851978"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f be 44 05 ?? 48 63 8d 64 01 00 00 0f be 8c 0d a4 00 00 00 33 ?? 48 63 8d 84 01 00 00 88 84 0d ?? ?? ?? ?? 8b 85 64 01 00 00 ff c0 89 85 64 01 00 00 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_RB_2147888165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.RB!MTB"
        threat_id = "2147888165"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 28 33 c0 83 f8 01 74 0d b9 60 ea 00 00 ff 15 ?? ?? ?? ?? eb ec 48 83 c4 28 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_ACN_2147889121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.ACN!MTB"
        threat_id = "2147889121"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Elevation:Administrator!new:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" wide //weight: 1
        $x_1_2 = "14NitroInstaller" ascii //weight: 1
        $x_1_3 = "14NitrogenAction" ascii //weight: 1
        $x_1_4 = "14NitrogenStager" ascii //weight: 1
        $x_1_5 = "14NitrogenTarget" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_H_2147890062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.H!MTB"
        threat_id = "2147890062"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 8b 44 24 ?? 48 8b 4c 24 ?? ba 10 66 00 00 45 31 c9 48 8d 44 24 ?? 48 89 44 24}  //weight: 2, accuracy: Low
        $x_2_2 = {4c 8b 54 24 ?? 48 8b 4c 24 ?? 31 c0 89 c2 45 31 c9 48 8d 44 24 ?? 45 89 c8 4c 89 54 24 ?? 48 89 44 24}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_I_2147891507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.I!MTB"
        threat_id = "2147891507"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 f7 f1 48 8b c2 89 45 ?? 48 63 45 24 48 8b 8d ?? ?? ?? ?? 0f b6 04 01 48 63 4d ?? 0f be 4c 0d 04 33 c1 48 63 4d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_J_2147891578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.J!MTB"
        threat_id = "2147891578"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 98 8b 84 85 ?? ?? ?? ?? 48 98 48 8b 95 ?? ?? ?? ?? 48 01 c2 8b 85 ?? ?? ?? ?? 48 98 0f b6 ?? ?? ?? 88 02 83 85}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_K_2147895234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.K!MTB"
        threat_id = "2147895234"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c9 48 83 f8 ?? 48 0f 46 c8 42 0f b6 04 ?? 41 30 04 18 48 8d 41}  //weight: 2, accuracy: Low
        $x_2_2 = "Decrypting shellcode" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_L_2147895774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.L!MTB"
        threat_id = "2147895774"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {39 7c 24 58 74 ?? 48 8d 54 24 50 48 8b cb ff 15 ?? ?? 00 00 85 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {41 8b 3e 48 8d 15 ?? ?? 00 00 48 03 fd 48 8b cf e8 ?? ?? 00 00 85 c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_M_2147907802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.M!MTB"
        threat_id = "2147907802"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 37 41 8b de 49 03 f1 48 8d 7f ?? 0f be 0e 48 ff c6 c1 cb ?? 03 d9 84 c9}  //weight: 2, accuracy: Low
        $x_2_2 = {41 8d 0c 30 45 03 ?? 80 34 ?? ?? 44 3b c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_N_2147908185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.N!MTB"
        threat_id = "2147908185"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {42 0f b6 0c 12 41 88 08 46 88 0c 12 41 0f b6 10 49 03 d1 0f b6 ca 0f b6 14 ?? 30 13 48 ff c3 49 83 eb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_O_2147910755_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.O!MTB"
        threat_id = "2147910755"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {55 53 48 83 ec 38 48 8d 6c 24 30 48 8d 45 fc 49 89 c1 41 b8 40 00 00 00 ba ?? ?? ?? 00 48 8d 0d 79 0a 01 00 48 8b 05 ?? ?? 05 00 ff d0 85 c0 75 ?? 48 8b 05 ?? ?? 05 00 ff d0 89 c3 b9 02 00 00 00 48 8b 05 25 ?? 05 00 ff d0 41 89 d8 48 8d 15 29 ?? 05 00 48 89 c1 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_RU_2147910897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.RU!MTB"
        threat_id = "2147910897"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 44 24 48 48 8d 85 20 02 00 00 48 89 44 24 40 48 89 74 24 38 48 89 74 24 30 c7 44 24 28 00 00 00 08 89 74 24 20 45 33 c9 45 33 c0 48 8d 95 a0 03 00 00 33 c9 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "Del /f /q \"%s\"" ascii //weight: 1
        $x_1_3 = "Users\\sSs\\source\\repos\\Test\\x64\\Release\\Test.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_RW_2147911807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.RW!MTB"
        threat_id = "2147911807"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UXN+bXBwZTM5MjQkLFttcmhze3ckUlgkNTQyND8kW21yOjg/JHw6OC0kRXR0cGlbaWZPbXgzOTc7Mjc6JCxPTFhRUDAk" wide //weight: 1
        $x_1_2 = "cG1vaSRLaWdvcy0kR2x2c3FpMzU1NDI0MjQyNCRXZWpldm0zOTc7Mjc6M3xpem1w" wide //weight: 1
        $x_1_3 = "Add-MpPreference -ExclusionPath C:" wide //weight: 1
        $x_1_4 = "R3R0cXQ8VXFvZ3Zqa3BpInlncHYieXRxcGkj" wide //weight: 1
        $x_1_5 = "WGxpJGlyeGl2aWgkaGV4ZSRtdyRtcmdzdnZpZ3gl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_P_2147912991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.P!MTB"
        threat_id = "2147912991"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 0f be 0c 39 b8 ?? ?? ?? ?? 49 ff c1 f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 d0 41 8b c2 69 d2 ?? ?? ?? ?? 2b ca 80 c1 4f 41 30 0b 25}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_Q_2147915193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.Q!MTB"
        threat_id = "2147915193"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f 95 c4 44 87 e2 41 55 88 de 66 44 0f b6 e9 4c 8d 24 65 ?? ?? ?? ?? 41 53 66 45 87 ec 4c 0f b6 eb f3 9c}  //weight: 2, accuracy: Low
        $x_2_2 = {4c 0f be e9 66 41 f7 d4 41 50 66 0f bb ff f8 0f 95 c3 66 0f b6 c2 41 56}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_NE_2147925797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.NE!MTB"
        threat_id = "2147925797"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 4c 24 ?? 48 85 f6 74 3f 4c 8d 05 6b 30 fe ff 48 3b ca 73 33 80 39 ?? 75 14 48 8d 42 ?? 48 3b c8 73 1a 80 79 01 ?? 75 14 48 ff c1 eb 0f 0f b6 01 4a 0f be 84 00 ?? ?? ?? ?? 48 03 c8 48 ff c7 48 ff c1 48 3b fe}  //weight: 3, accuracy: Low
        $x_1_2 = "Target function called!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_NS_2147929587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.NS!MTB"
        threat_id = "2147929587"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "shellcode" ascii //weight: 2
        $x_1_2 = "explorer.exe" ascii //weight: 1
        $x_1_3 = "LdrpDllNotificationList" ascii //weight: 1
        $x_1_4 = "IsProcessorFeaturePresent" ascii //weight: 1
        $x_1_5 = "Successfully registered dummy callback" ascii //weight: 1
        $x_1_6 = "trampoline has been written to remote process" ascii //weight: 1
        $x_1_7 = "Shellcode has been written to remote process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shelm_NM_2147931582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shelm.NM!MTB"
        threat_id = "2147931582"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {4f 8d 04 27 41 b9 0d 00 00 00 4d 29 e1 4c 89 f1 48 89 fa e8 ?? ?? 00 00 0f b7 44 24 58 66 85 c0 75 ?? 4c 03 64 24 50}  //weight: 3, accuracy: Low
        $x_2_2 = {49 83 fc 0d 75 ?? 48 8d 15 dc 48 07 00 4c 8d 84 24 80 00 00 00 48 89 d9 e8 ?? ?? 01 00 66 85 c0 0f 84 ?? ?? 00 00 66 83 f8 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

