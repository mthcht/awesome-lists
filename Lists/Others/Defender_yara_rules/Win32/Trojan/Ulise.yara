rule Trojan_Win32_Ulise_OS_2147744200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.OS!MTB"
        threat_id = "2147744200"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 14 4e 84 d2 75 0a 38 54 4e 01 74 0c 3b cb 7d 08 f6 d2 88 14 01 41 eb e7 c6 04 01 00 66 39 7c 4e 02 5f 5e 5b}  //weight: 1, accuracy: High
        $x_1_2 = "ChangeServiceConfig2A" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_BO_2147837420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.BO!MTB"
        threat_id = "2147837420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 08 8d 4e 01 8a 04 06 88 04 1a 8b c2 33 d2 8b 75 14 f7 75 10 ff 45 fc 03 f1 85 d2 8b 55 fc 0f 45 f1 3b 55 0c 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_AMS_2147851793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.AMS!MTB"
        threat_id = "2147851793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MinerManager" ascii //weight: 1
        $x_1_2 = "KeyLogger" ascii //weight: 1
        $x_1_3 = "schtasks.exe /CREATE /RL HIGHEST /SC ONLOGON /TR" ascii //weight: 1
        $x_1_4 = "outdated_core.exe" ascii //weight: 1
        $x_1_5 = "AnalDestroyer.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_GMX_2147893349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.GMX!MTB"
        threat_id = "2147893349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {89 d8 c1 e0 05 8b 55 fc 8b 54 02 14 51 29 d1 8a 02 88 04 11 83 c2 01 84 c0 75}  //weight: 10, accuracy: High
        $x_1_2 = ".edlwv" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_GAB_2147898651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.GAB!MTB"
        threat_id = "2147898651"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b c6 89 45 08 33 c9 8d 14 30 8a 04 0f 41 88 02 8d 52 04 83 f9 04 ?? ?? 8b 45 08 46 83 c7 04 3b f3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_ASEG_2147901048_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.ASEG!MTB"
        threat_id = "2147901048"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d2 6a 14 8b c1 5e f7 f6 8b 45 08 8a 04 02 30 04 19 41 3b cf 72}  //weight: 2, accuracy: High
        $x_2_2 = {81 ec 74 01 00 00 53 56 57 6a ff ff 35}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_AI_2147905953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.AI!MTB"
        threat_id = "2147905953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff 75 35 e8 ?? ?? ?? ?? 05 50 c3 00 00 33 d2 89 45 d8 89 55 dc e8 ?? ?? ?? ?? 33 d2 3b 55}  //weight: 5, accuracy: Low
        $x_5_2 = {2a 18 30 8a ?? ?? ?? ?? 14 70 b2 62 7b}  //weight: 5, accuracy: Low
        $x_1_3 = {5a 36 be f4 9d e5 99 b9 df 59 74 a7 bf 43 ce 61 b9 b5 e1}  //weight: 1, accuracy: High
        $x_1_4 = "shenhua.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_A_2147908937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.A!MTB"
        threat_id = "2147908937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b f0 8d 85 d8 fe ff ff 50 56 c7 85 d8 fe ff ff 28 01 00 00 e8 ?? ?? 00 00 85 c0 74 ?? 39 bd e0 fe ff ff 74 ?? 8d 85 d8 fe ff ff 50 56 e8}  //weight: 2, accuracy: Low
        $x_2_2 = {80 74 05 e8 ?? 40 83 f8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_NOAA_2147911372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.NOAA!MTB"
        threat_id = "2147911372"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {56 53 8b 4e 10 c1 e9 02 8b 76 0c 03 35 75 21 40 00 f3 a5 5b 5e 83 c6 28 4b 75 e5 0f 31 bb f4 40 40 00 bf 68 21 40 00 b9 04 00 00 00 3c 3d 76 04 2c 3d eb f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_GXU_2147912618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.GXU!MTB"
        threat_id = "2147912618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {69 51 c6 44 24 ?? 6d c6 44 24 ?? 6d c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 c6 44 24 ?? 6c c6 44 24 ?? 6c c6 44 24 ?? 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 0f 84}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_AUL_2147927001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.AUL!MTB"
        threat_id = "2147927001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b 17 52 e8 ?? ?? ?? ?? a3 7c 3d 45 00 8d 8b b4 01 00 00 51 8b 07 50 e8 ?? ?? ?? ?? a3 80 3d 45 00 8d 93 c3 01 00 00 52 8b 0f 51 e8 ?? ?? ?? ?? a3 84 3d 45 00 8d 83 d6 01 00 00 50 8b 17 52}  //weight: 1, accuracy: Low
        $x_2_2 = {6a 08 6a 00 52 e8 ?? ?? ?? ?? 8b f0 89 37 85 f6 0f 84 2c 01 00 00 8d 83 09 01 00 00 50 56 e8 ?? ?? ?? ?? a3 5c 3d 45 00 8d 93 19 01 00 00 52 8b 0f 51 e8 ?? ?? ?? ?? a3 60 3d 45 00 8d 83 29 01 00 00 50 8b 17 52 e8 ?? ?? ?? ?? a3 64 3d 45 00 8d 8b 39 01 00 00 51 8b 07 50}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_NE_2147956769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.NE!MTB"
        threat_id = "2147956769"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b d8 0f b7 83 ?? 00 00 00 66 85 c0 74 14 0f b7 c0 50 6a 00 e8 66 cd ?? ff 66 c7 83}  //weight: 2, accuracy: Low
        $x_1_2 = {8d 55 fc a1 30 78 51 00 e8 97 c1 ?? ff 8b 4d fc b2 01 a1 04 6c 41 00 e8 38 23 ?? ff e8 6b 9a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ulise_GTD_2147959366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ulise.GTD!MTB"
        threat_id = "2147959366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ulise"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c1 e2 0d 33 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? c1 e8 11 33 05}  //weight: 5, accuracy: Low
        $x_5_2 = {c6 45 fc 4e c6 45 fd 74 c6 45 fe 00 c6 45 d0 43 c6 45 d1 72 c6 45 d2 65 c6 45 d3 61 c6 45 d4 74 c6 45 d5 65 c6 45 d6 00 c6 45 d8 46 c6 45 d9 69 c6 45 da 6c c6 45 db 65}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

