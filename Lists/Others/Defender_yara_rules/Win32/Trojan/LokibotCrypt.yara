rule Trojan_Win32_LokibotCrypt_J_2147763943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokibotCrypt.J!MTB"
        threat_id = "2147763943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokibotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 5d fc 8a 1c 03 80 f3 ?? 8b ca 03 c8 73 05 e8 ?? ?? ?? ?? 88 19 80 31 ?? 40 4e 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokibotCrypt_RK_2147764691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokibotCrypt.RK!MTB"
        threat_id = "2147764691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokibotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 6a 01 ff d6 b8 00 00 00 00 f7 f0 [0-31] 6a 00 6a 00 e8 [0-4] 89 f6 [0-31] 8b c7 [0-31] 5f 5e 5b c3}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 00 00 00 00 f7 f0 83 e8 00 83 e8 00 83 e8 00 83 e8 00 83 e8 00 6a 00 6a 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {8a 45 fa 32 45 f9 88 01 83 e8 00 [0-31] 8a 55 fb 8b c1 [0-10] 83 e8 00 [0-10] [0-31] 88 01}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 10 32 55 fb 88 11 [0-31] 8a 55 fa 30 11 [0-31] 47 40 4e 75}  //weight: 1, accuracy: Low
        $x_1_5 = {00 b8 00 00 00 00 f7 f0 89 f6 [0-31] 8b c6 5e 5b 5d c3}  //weight: 1, accuracy: Low
        $x_1_6 = {32 55 fb 88 11 [0-31] 8a 55 fa 30 11 3f 00 8a 10}  //weight: 1, accuracy: Low
        $x_1_7 = {b8 00 00 00 00 f7 f0 83 e8 00 [0-31] 6a 00 6a 00 6a 00 e8 [0-31] 8b c6 5e 5b 5d c3}  //weight: 1, accuracy: Low
        $x_1_8 = {b8 00 00 00 00 f7 f0 8b c6 5e 5b 5d c3 2f 00 68 ?? ?? ?? 00 6a 01 (e8|ff 15)}  //weight: 1, accuracy: Low
        $x_1_9 = {b8 00 00 00 00 f7 f0 8b c6 5e 5b c3 2f 00 68 ?? ?? ?? 00 6a 01 ff 15}  //weight: 1, accuracy: Low
        $x_1_10 = {03 f3 8a 01 88 45 ?? 8b c3 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 ?? 8a 45 ?? 32 45 ?? 88 06 8a 45 ?? 30 06 eb ?? 8a 45 ?? 88 06 43 41 4f 75}  //weight: 1, accuracy: Low
        $x_1_11 = {8a 45 f6 32 45 f5 88 01 83 e8 00 8a 55 f7 8b c1 e8 [0-31] 88 01 [0-31] 46 43 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_LokibotCrypt_MR_2147772805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokibotCrypt.MR!MTB"
        threat_id = "2147772805"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokibotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3b c7 7c c3 41 00 69 [0-5] 89 [0-5] 89 [0-5] 81 [0-9] 8b [0-5] 03 [0-5] 40 89 [0-5] 8a [0-5] 30}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokibotCrypt_MS_2147772806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokibotCrypt.MS!MTB"
        threat_id = "2147772806"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokibotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 01 42 3b [0-3] 8b [0-3] 8d ?? ?? 55 8b ec ?? a1 [0-16] a3 [0-4] 81 [0-6] 8b [0-3] 01 [0-5] 0f [0-6] 25 [0-8] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokibotCrypt_2147772811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokibotCrypt.MT!MTB"
        threat_id = "2147772811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokibotCrypt"
        severity = "Critical"
        info = "MT: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {30 04 0a 41 3b ce 55 8b ec ?? a1 [0-16] a3 [0-4] 81 [0-6] 8b [0-3] 01 [0-5] 0f [0-6] 25 [0-8] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokibotCrypt_MU_2147772871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokibotCrypt.MU!MTB"
        threat_id = "2147772871"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokibotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 ff 16 05 00 00 46 3b f7 e8 ?? ?? ?? ?? 30}  //weight: 1, accuracy: Low
        $x_1_2 = {55 8b ec 51 [0-4] 53 b8 [0-4] 8b [0-5] 01 [0-2] 01 [0-2] 8b [0-2] 8a [0-2] 8b [0-5] 88 [0-5] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokibotCrypt_MV_2147775377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokibotCrypt.MV!MTB"
        threat_id = "2147775377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokibotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 30 [0-2] 83 [0-2] 46 3b f7 a1 [0-4] 69 [0-5] 05 [0-4] a3 [0-4] 0f [0-6] 81 [0-5] 81 [0-9] 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LokibotCrypt_KM_2147776127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LokibotCrypt.KM!MTB"
        threat_id = "2147776127"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LokibotCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 31 81 3d ?? ?? ?? ?? 03 02 00 00 75 ?? 53 53 ff 15 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 46 3b 35 ?? ?? ?? ?? 72 13 00 a1 ?? ?? ?? ?? 8a 84 30 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 88}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 3b 83 7d ?? 19 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

