rule Trojan_Win32_Matanbuchus_QW_2147806069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matanbuchus.QW!MTB"
        threat_id = "2147806069"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "29"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 45 e4 bb 03 00 00 00 33 5d 08 83 c3 37 2b 5d 10 83 c3 68}  //weight: 10, accuracy: High
        $x_10_2 = {83 c6 57 81 ee 54 6b b6 93 33 75 1c 81 c6 30 e2 71 d9}  //weight: 10, accuracy: High
        $x_3_3 = "SzToWz" ascii //weight: 3
        $x_3_4 = "CmBuildFullPathFromRelativeW" ascii //weight: 3
        $x_3_5 = "Qm7kljQTRKhBcOve3JPpwE4XOoZcy" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matanbuchus_DA_2147918562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matanbuchus.DA!MTB"
        threat_id = "2147918562"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "B:\\LoadDll6\\LoadDll\\result\\Release\\libcurl.pdb" ascii //weight: 20
        $x_1_2 = "DllInitialize" ascii //weight: 1
        $x_1_3 = "DllInstall" ascii //weight: 1
        $x_1_4 = "RegisterDll" ascii //weight: 1
        $x_1_5 = "ThreadFunction" ascii //weight: 1
        $x_1_6 = "curl_easy_cleanup" ascii //weight: 1
        $x_1_7 = "curl_easy_init" ascii //weight: 1
        $x_1_8 = "curl_easy_perform" ascii //weight: 1
        $x_1_9 = "curl_easy_setopt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matanbuchus_A_2147928558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matanbuchus.A!MTB"
        threat_id = "2147928558"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 f0 8b 42 14 89 45 e8 33 c9 66 89 4d fc}  //weight: 1, accuracy: High
        $x_1_2 = {03 51 20 89 55 dc 8b 45 f4 8b 4d 08 03 48 1c 89 4d cc c7 45}  //weight: 1, accuracy: High
        $x_1_3 = {8b 55 ec 81 3a 50 45 00 00 74 07 33 c0 e9}  //weight: 1, accuracy: High
        $x_1_4 = {8b 45 e8 8b 4d 08 03 48 3c 89 4d ec 8b 55 ec}  //weight: 1, accuracy: High
        $x_1_5 = {8b 45 08 89 45 f8 8b 4d f8 8b 51 3c 03 55 08}  //weight: 1, accuracy: High
        $x_1_6 = {69 c2 93 01 00 01 50 b9 01 00 00 00 c1 e1 00 03 4d 08 51 e8}  //weight: 1, accuracy: High
        $x_1_7 = {03 45 08 89 45 e0 8b 4d e0 8b 51 78 03 55 08 89 55 f0 8b 45 f0}  //weight: 1, accuracy: High
        $x_1_8 = {89 55 f4 8b 45 f4 83 78 04 00 0f 84 a6 00 00 00 8b 4d f4}  //weight: 1, accuracy: High
        $x_1_9 = {89 4d ec 8b 55 ec 81 3a 50 45 00 00 74 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matanbuchus_GKN_2147930833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matanbuchus.GKN!MTB"
        threat_id = "2147930833"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 ff 64 a1 30 00 00 00 53 56 57 8b 40 0c 8b 40 0c 8b 50 18 8b 4a 3c 8b 4c 11 78 03 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matanbuchus_ASJ_2147931599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matanbuchus.ASJ!MTB"
        threat_id = "2147931599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {f7 d2 2b c2 03 c8}  //weight: 2, accuracy: High
        $x_2_2 = {f7 d1 f7 d2 89 0d}  //weight: 2, accuracy: High
        $x_1_3 = {2b c1 f7 d0 0f b7 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matanbuchus_AUJ_2147932418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matanbuchus.AUJ!MTB"
        threat_id = "2147932418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 89 85 e8 fe ff ff 89 95 ec fe ff ff b8 56 27 09 00 c7 85 e0 fe ff ff 7e 6a 48 f5 89 85 e4 fe ff ff c7 85 f0 fe ff ff 1b 00 00 00 8b 0d d0 b0 07 10 66 89 4d 9c 33 d2 c7 85 d8 fe ff ff fd 00 00 00 89 95 dc fe ff ff b8 7b 29 0e 00 c7 85 d0 fe ff ff 26 ae 1e 62 89 85 d4 fe ff ff b9 54 3f 00 00 66 89 4d 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matanbuchus_MKZ_2147933800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matanbuchus.MKZ!MTB"
        threat_id = "2147933800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 c0 99 83 f0 5f b9 01 00 00 00 6b d1 00 88 84 15 28 f8 ff ff 6a 3e e8 ?? ?? ?? ?? 83 c4 04 0f b6 c0 99 83 f0 5f b9 01 00 00 00 c1 e1 00 88 84 0d 28 f8 ff ff 6a 73 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Matanbuchus_CCIM_2147946885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Matanbuchus.CCIM!MTB"
        threat_id = "2147946885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Matanbuchus"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f8 83 c0 01 8b 4d fc 83 d1 00 89 45 f8 89 4d fc 8b 55 fc 3b 55 10}  //weight: 2, accuracy: High
        $x_2_2 = {6a 00 6a 01 8b 4d fc 51 8b 55 f8 52 e8 ?? ?? ?? ?? 8b f0 6a 00 6a 08 8b 45 fc 50 8b 4d f8 51 e8}  //weight: 2, accuracy: Low
        $x_1_3 = {0f be d0 8b 45 08 0f be 1c 30 33 da 6a 00 6a 01 8b 4d fc 51 8b 55 f8 52 e8 ?? ?? ?? ?? 8b 4d 08 88 1c 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

