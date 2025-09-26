rule Trojan_Win32_Virlock_BS_2147829364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.BS!MTB"
        threat_id = "2147829364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 06 90 32 c2 90 88 07 90 e9}  //weight: 4, accuracy: High
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_GMH_2147891348_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.GMH!MTB"
        threat_id = "2147891348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {40 00 fc 3a 40 00 e8 ?? ?? ?? ?? 5c 40 00 10 3b 40 00 04 3b 40 00 04 5d 40 00 98 38 40 00 d4 38 40 00}  //weight: 10, accuracy: Low
        $x_1_2 = "oE8MnOt" ascii //weight: 1
        $x_1_3 = "P.vmp0" ascii //weight: 1
        $x_1_4 = ".vmp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_GMH_2147891348_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.GMH!MTB"
        threat_id = "2147891348"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 0c 3b 40 00 10 3b 40 00 04 3b 40 00 7c 38 40 00 98 ?? ?? ?? ?? 38 40 00 0a 45 4c 69 73 ?? 45 72 72 6f}  //weight: 10, accuracy: Low
        $x_1_2 = "VOU7uuxu" ascii //weight: 1
        $x_1_3 = "zAuNviEU" ascii //weight: 1
        $x_1_4 = "P.vmp0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_NV_2147897385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.NV!MTB"
        threat_id = "2147897385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 06 32 c2 88 07 42 [0-10] 49 83 f9 00}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_NV_2147897385_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.NV!MTB"
        threat_id = "2147897385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 06 32 c2 88 07 42 46 47 49 83 f9 00 0f 85 ed ff ff ff e9 2a 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {89 07 8b f8 8b df b9 ?? 03 00 00 ba ?? 00 00 00 e9 be ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_NV_2147897385_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.NV!MTB"
        threat_id = "2147897385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e9 cb e3 ff ff ff d1 43 c1 c6 ?? 33 f7 8b d6 e9 fe 02 00 00 68 ?? ?? ?? ?? c1 e7 1a 03 da 87 f7 81 c2 ?? ?? ?? ?? 03 f7 03 df}  //weight: 2, accuracy: Low
        $x_3_2 = {8b fe 33 df 47 2b fb 81 ca ?? ?? ?? ?? f7 da 2b d6 81 f2 ?? ?? ?? ?? c1 ef 10 c1 ca ?? c1 ee 14 e9 6c 01 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_ARA_2147897708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.ARA!MTB"
        threat_id = "2147897708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 32 c2 e9}  //weight: 2, accuracy: High
        $x_2_2 = {88 07 90 46 47 49 90 83 f9 00 90 0f 85}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_EC_2147907197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.EC!MTB"
        threat_id = "2147907197"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {b9 00 04 00 00 ba 04 00 00 00 8a 06 32 c2 90 e9 b8 ff ff ff}  //weight: 2, accuracy: High
        $x_2_2 = {89 07 90 8b f8 8b df 90 e9 34 00 00 00 88 07 42 46 47 90 49 90 83 f9 00 90 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_PADQ_2147913608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.PADQ!MTB"
        threat_id = "2147913608"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 6e 00 00 00 8a 06 90 32 c2 90 88 07 90 42 46 47 90 49 90 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_ARAX_2147945734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.ARAX!MTB"
        threat_id = "2147945734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 32 c2 90 e9}  //weight: 2, accuracy: High
        $x_2_2 = {88 07 42 90 46 47}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_ARAX_2147945734_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.ARAX!MTB"
        threat_id = "2147945734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 06 32 c2 e9 ?? 00 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {88 07 46 90 47}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_LMX_2147948035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.LMX!MTB"
        threat_id = "2147948035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 06 90 32 c2 88 07 42 46 90 47 90 49 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_SL_2147948061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.SL!MTB"
        threat_id = "2147948061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 06 90 32 c2 88 07 90 e9 c5 ff ff ff}  //weight: 2, accuracy: High
        $x_2_2 = {42 46 47 90 49}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_VMX_2147948477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.VMX!MTB"
        threat_id = "2147948477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 06 90 32 c2 88 07 90 42 46 90 47 49 90}  //weight: 5, accuracy: High
        $x_5_2 = {88 07 90 46 47 49 83 f9 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Virlock_NC_2147949049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.NC!MTB"
        threat_id = "2147949049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {32 c2 88 07 [0-4] 49 83 f9 00}  //weight: 2, accuracy: Low
        $x_2_2 = {8a 06 32 c2 88 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 07 8b f8}  //weight: 2, accuracy: Low
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Virlock_NE_2147949075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.NE!MTB"
        threat_id = "2147949075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 06 32 c2 88 07 [0-14] 83 f9 00 0f}  //weight: 2, accuracy: Low
        $x_1_2 = "VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Virlock_PAGD_2147953249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Virlock.PAGD!MTB"
        threat_id = "2147953249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8a 06 32 c2 88 07 42 46 [0-2] e9}  //weight: 3, accuracy: Low
        $x_5_2 = {6a 40 68 00 30 00 00 68 00 ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? c3}  //weight: 5, accuracy: Low
        $x_5_3 = {6a 40 68 00 10 00 00 68 00 ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

