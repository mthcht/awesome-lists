rule Trojan_Win32_CerberCrypt_A_2147840691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.A!MTB"
        threat_id = "2147840691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 32 c2 88 07 42 46 47 e9}  //weight: 2, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_B_2147847645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.B!MTB"
        threat_id = "2147847645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 10 8b 45 08 03 45 ?? 0f b6 08 33 ca 8b 55 ?? 03 55 d4 88 0a e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_C_2147847964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.C!MTB"
        threat_id = "2147847964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 0c 02 8b 55 ?? 03 55 ?? 8b 45 ?? 8a 04 10 32 c1 88 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_D_2147906001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.D!MTB"
        threat_id = "2147906001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b f8 90 8b df}  //weight: 2, accuracy: High
        $x_2_2 = {8a 06 90 32 c2}  //weight: 2, accuracy: High
        $x_2_3 = {6a 40 68 00 30 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_E_2147906334_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.E!MTB"
        threat_id = "2147906334"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 32 c2 88 07}  //weight: 2, accuracy: High
        $x_2_2 = {42 90 46 90}  //weight: 2, accuracy: High
        $x_2_3 = {47 90 49 83 f9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_F_2147906438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.F!MTB"
        threat_id = "2147906438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 90 32 c2 90 88 07 90 42 90 46 47 49 83 f9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_G_2147906652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.G!MTB"
        threat_id = "2147906652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {32 c2 88 07 90 42 90 46}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_H_2147908912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.H!MTB"
        threat_id = "2147908912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 32 c2 90 88 07 90 42 46 90}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_I_2147909100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.I!MTB"
        threat_id = "2147909100"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 32 c2 88 07 46 47 49 90 83 f9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_J_2147910807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.J!MTB"
        threat_id = "2147910807"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 90 32 c2 88 07}  //weight: 2, accuracy: High
        $x_2_2 = {6a 40 90 68 00 10 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_K_2147910898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.K!MTB"
        threat_id = "2147910898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 40 68 00 10 00 00 90}  //weight: 2, accuracy: High
        $x_2_2 = {8a 06 90 32 c2 88 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_L_2147911015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.L!MTB"
        threat_id = "2147911015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6a 40 68 00 10 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {8a 06 90 32 c2 90 88 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_CMX_2147947880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.CMX!MTB"
        threat_id = "2147947880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 32 c2 88 07 90 46 90 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_CMX_2147947880_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.CMX!MTB"
        threat_id = "2147947880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {42 90 46 47 49 90 83 f9 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 06 32 c2 90 88 07 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CerberCrypt_CMX_2147947880_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.CMX!MTB"
        threat_id = "2147947880"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 90 32 c2 90 88 07 90}  //weight: 1, accuracy: High
        $x_1_2 = {46 90 47 90 49 90 83 f9 00 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CerberCrypt_MX_2147947894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.MX!MTB"
        threat_id = "2147947894"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 c2 90 88 07 90 42 90 46 90 47 90 49 90 83 f9}  //weight: 1, accuracy: High
        $x_1_2 = {8a 06 90 32 c2 88 07 42 46 47 49 90 83 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_CerberCrypt_RMX_2147949047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CerberCrypt.RMX!MTB"
        threat_id = "2147949047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CerberCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 06 32 c2 88 07 42 46 90 47}  //weight: 5, accuracy: High
        $x_5_2 = {8a 06 90 32 c2 88 07 90 42 46 47}  //weight: 5, accuracy: High
        $x_1_3 = {6a 40 68 00 10 00 00 68}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

