rule Trojan_Win32_NSISInject_FJ_2147799518_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FJ!MTB"
        threat_id = "2147799518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff}  //weight: 1, accuracy: High
        $x_1_2 = {68 00 a3 e1 11 68 de 00 00 00 ff 75 f4 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FJ_2147799518_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FJ!MTB"
        threat_id = "2147799518"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 0c 6a 40 68 00 30 00 00 68 49 13 00 00 57 ff 15}  //weight: 10, accuracy: High
        $x_1_2 = {88 04 3e 47 3b fb 72 ?? 6a 00 56 ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_D_2147805124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.D!MTB"
        threat_id = "2147805124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 fc 00 00 00 00 68 00 a3 e1 11 6a 01 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\xampp\\htdocs\\Loct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DA_2147805520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DA!MTB"
        threat_id = "2147805520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 e0 00 00 00 00 c7 04 24 00 00 00 00 c7 44 24 04 00 a3 e1 11 c7 44 24 08 00 30 00 00 c7 44 24 0c 04 00 00 00 89 45 dc ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\xampp\\htdocs\\Loct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DB_2147805523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DB!MTB"
        threat_id = "2147805523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 fc 00 00 00 00 6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {c1 fa 05 0f b6 05 ?? ?? ?? ?? c1 e0 03 0b d0 88 15 ?? ?? ?? ?? 0f b6 0d 1f 00 a2 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
        $x_1_3 = {f7 da 88 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? c1 f8 05 0f b6 0d ?? ?? ?? ?? c1 e1 03 0b c1 a2 ?? ?? ?? ?? 0f b6 15 1f 00 a2 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 81 c1 ed 00 00 00 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_E_2147805551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.E!MTB"
        threat_id = "2147805551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 fc 00 00 00 00 6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = "C:\\xampp\\htdocs\\Loct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DC_2147806169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DC!MTB"
        threat_id = "2147806169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 dc 00 00 00 00 c7 04 24 00 00 00 00 c7 44 24 04 00 a3 e1 11 c7 44 24 08 00 30 00 00 c7 44 24 0c 04 00 00 00 89 45 d8 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {c1 fe 02 0f b6 3d ?? ?? ?? ?? c1 e7 06 89 f1 09 f9 88 0d ?? ?? ?? ?? 8b 35 0d 00 88 0d ?? ?? ?? ?? 0f b6 35}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 fe 01 0f b6 3d ?? ?? ?? ?? c1 e7 07 89 f1 09 f9 88 0d ?? ?? ?? ?? 0f b6 35 0d 00 88 0d ?? ?? ?? ?? 0f b6 35}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 fe 02 0f b6 3d ?? ?? ?? ?? c1 e7 06 89 f1 09 f9 88 0d ?? ?? ?? ?? 0f b6 35 0d 00 88 0d ?? ?? ?? ?? 0f b6 35}  //weight: 1, accuracy: Low
        $x_1_5 = {c1 fe 03 0f b6 3d ?? ?? ?? ?? c1 e7 05 89 f1 09 f9 88 0d ?? ?? ?? ?? 0f b6 35 0d 00 88 0d ?? ?? ?? ?? 0f b6 35}  //weight: 1, accuracy: Low
        $x_1_6 = {c1 f8 05 0f b6 0d ?? ?? ?? ?? c1 e1 03 0b c1 a2 ?? ?? ?? ?? 0f b6 15 20 00 88 0d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 0f b6 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_DD_2147806170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DD!MTB"
        threat_id = "2147806170"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 fc 00 00 00 00 6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {c1 f8 05 0f b6 0d ?? ?? ?? ?? c1 e1 03 0b c1 a2 ?? ?? ?? ?? 0f b6 15 1f 00 a2 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 0f b6 05}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 f9 05 0f b6 15 ?? ?? ?? ?? c1 e2 03 0b ca 88 0d ?? ?? ?? ?? 0f b6 05 1f 00 88 0d ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 0d}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 f8 05 0f b6 0d ?? ?? ?? ?? c1 e1 03 0b c1 a2 ?? ?? ?? ?? 0f b6 15 20 00 88 0d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 0f b6 05}  //weight: 1, accuracy: Low
        $x_1_5 = {c1 f9 03 0f b6 15 ?? ?? ?? ?? c1 e2 05 0b ca 88 0d ?? ?? ?? ?? 0f b6 05 1f 00 88 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_F_2147806225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.F!MTB"
        threat_id = "2147806225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 dc 00 00 00 00 c7 04 24 00 00 00 00 c7 44 24 04 00 a3 e1 11 c7 44 24 08 00 30 00 00 c7 44 24 0c 04 00 00 00 89 45 d8 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DE_2147806262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DE!MTB"
        threat_id = "2147806262"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 fc 00 00 00 00 6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {d1 fa 0f b6 05 ?? ?? ?? ?? c1 e0 07 0b d0 88 15 ?? ?? ?? ?? 0f b6 0d 1f 00 a2 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
        $x_1_3 = {d1 fa 0f b6 05 ?? ?? ?? ?? c1 e0 07 0b d0 88 15 ?? ?? ?? ?? 0f b6 0d 1f 00 a2 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 fa 02 0f b6 05 ?? ?? ?? ?? c1 e0 06 0b d0 88 15 ?? ?? ?? ?? 0f b6 0d 1f 00 a2 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_DF_2147806263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DF!MTB"
        threat_id = "2147806263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {c7 45 fc 00 00 00 00 6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {c1 fa 03 0f b6 05 ?? ?? ?? ?? c1 e0 05 0b d0 88 15 ?? ?? ?? ?? 0f b6 0d 1f 00 a2 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 fa 06 0f b6 05 ?? ?? ?? ?? c1 e0 02 0b d0 88 15 ?? ?? ?? ?? 0f b6 0d 1f 00 a2 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 f8 07 0f b6 0d ?? ?? ?? ?? d1 e1 0b c1 a2 ?? ?? ?? ?? 8b 15 1f 00 a2 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 0f b6 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_DG_2147807423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DG!MTB"
        threat_id = "2147807423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 45 fc 6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 55 fc}  //weight: 5, accuracy: High
        $x_1_2 = {c1 f8 05 0f b6 0d ?? ?? ?? ?? c1 e1 03 0b c1 a2 ?? ?? ?? ?? 0f b6 15 1f 00 a2 ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 0f b6 05}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 fa 03 0f b6 05 ?? ?? ?? ?? c1 e0 05 0b d0 88 15 ?? ?? ?? ?? 0f b6 0d 20 00 88 15 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 03 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 f9 06 0f b6 15 ?? ?? ?? ?? c1 e2 02 0b ca 88 0d ?? ?? ?? ?? 0f b6 05 1f 00 88 0d ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 0d}  //weight: 1, accuracy: Low
        $x_1_5 = {c1 f9 05 0f b6 15 ?? ?? ?? ?? c1 e2 03 0b ca 88 0d ?? ?? ?? ?? 0f b6 05 1f 00 88 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_DH_2147807585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DH!MTB"
        threat_id = "2147807585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 8d ff fb ff ff 0f b6 b5 ff fb ff ff c1 fe ?? 0f b6 bd ff fb ff ff c1 e7 ?? 89 f1 09 f9 88 8d ff fb ff ff [0-7] 0f b6 b5 ff fb ff ff 89}  //weight: 1, accuracy: Low
        $x_1_2 = "IcoLeQ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DH_2147807585_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DH!MTB"
        threat_id = "2147807585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 45 fc 6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 55 fc}  //weight: 5, accuracy: High
        $x_1_2 = {c1 f9 06 0f b6 15 ?? ?? ?? ?? c1 e2 02 0b ca 88 0d ?? ?? ?? ?? 0f b6 05 1f 00 88 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 0d}  //weight: 1, accuracy: Low
        $x_1_3 = {f7 d1 88 0d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? c1 fa 02 0f b6 05 ?? ?? ?? ?? c1 e0 06 0b d0 88 15 ?? ?? ?? ?? 0f b6 0d 0c 00 a2 ?? ?? ?? ?? 0f b6 0d}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 fa 07 0f b6 05 ?? ?? ?? ?? d1 e0 0b d0 88 15 ?? ?? ?? ?? 0f b6 0d 1f 00 a2 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
        $x_1_5 = {f7 d2 88 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? c1 f8 07 0f b6 0d ?? ?? ?? ?? d1 e1 0b c1 a2 ?? ?? ?? ?? 0f b6 15 1f 00 a2 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 33 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_DI_2147807586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DI!MTB"
        threat_id = "2147807586"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 45 fc 6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 55 fc}  //weight: 5, accuracy: High
        $x_1_2 = {c1 f8 02 0f b6 0d ?? ?? ?? ?? c1 e1 06 0b c1 a2 ?? ?? ?? ?? 0f b6 15 20 00 88 0d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 0f b6 05}  //weight: 1, accuracy: Low
        $x_1_3 = {c1 f9 07 0f b6 15 ?? ?? ?? ?? d1 e2 0b ca 88 0d ?? ?? ?? ?? 0f b6 05 1f 00 88 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 0d}  //weight: 1, accuracy: Low
        $x_1_4 = {c1 f9 06 0f b6 15 ?? ?? ?? ?? c1 e2 02 0b ca 88 0d ?? ?? ?? ?? 0f b6 05 1f 00 88 15 ?? ?? ?? ?? 0f b6 05 ?? ?? ?? ?? 33 05 ?? ?? ?? ?? a2 ?? ?? ?? ?? 0f b6 0d}  //weight: 1, accuracy: Low
        $x_1_5 = {c1 fa 06 0f b6 05 ?? ?? ?? ?? c1 e0 02 0b d0 88 15 ?? ?? ?? ?? 0f b6 0d 1f 00 a2 ?? ?? ?? ?? 0f b6 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? 0f b6 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_DJ_2147807964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DJ!MTB"
        threat_id = "2147807964"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 45 dc c7 04 24 00 00 00 00 c7 44 24 04 00 a3 e1 11 c7 44 24 08 00 30 00 00 c7 44 24 0c 04 00 00 00 89 4d d8 ff 55}  //weight: 5, accuracy: High
        $x_1_2 = {c1 fe 02 0f b6 3d ?? ?? ?? ?? c1 e7 06 89 f0 09 f8 a2 ?? ?? ?? ?? 0f b6 35 1b 00 88 0d ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? 29 f0 a2 ?? ?? ?? ?? 0f b6 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DK_2147807966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DK!MTB"
        threat_id = "2147807966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {d1 f8 0f b6 0d ?? ?? ?? ?? c1 e1 07 0b c1 a2 ?? ?? ?? ?? 8b 15 20 00 88 0d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 33 15 ?? ?? ?? ?? 88 15 ?? ?? ?? ?? 0f b6 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DK_2147807966_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DK!MTB"
        threat_id = "2147807966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe c8 fe c0 fe c8 fe c8 fe c8 2c 77 fe c0 2c 7e 2c 51 2c 83 fe c8 fe c0 04 f6 fe c0 34 76 2c 48 fe c8 04 d3 2c cf 88 81 ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {34 1c 34 ad fe c0 fe c8 04 48 fe c0 fe c0 34 6f 34 e2 2c b4 34 72 04 0c fe c0 2c dc fe c8 fe c0 2c 06 fe c0 04 93 88 81 ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {04 2d 34 2a 2c 94 fe c8 2c 0f fe c0 fe c8 04 5a fe c0 fe c0 34 6b 2c 05 fe c0 2c b5 34 35 04 e4 34 f6 34 a9 fe c8 88 81 ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NSISInject_DL_2147807969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DL!MTB"
        threat_id = "2147807969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 e0 c7 45 f0 00 a3 e1 11 89 45 ec 8b 45 ec 89 45 e8 83 7d f0 00 0f 84 ?? ?? ?? ?? 8b 45 e8 c6 00 00 8b 45 e8 83 c0 01 89 45 e8 8b 45 f0 83 c0 ff 89 45 f0 e9}  //weight: 1, accuracy: Low
        $x_1_2 = "LLD PDB." ascii //weight: 1
        $x_1_3 = {78 61 6d 70 70 5c 68 74 64 6f 63 73 5c 4c 6f 63 74 5c [0-32] 5c 4c 6f 61 64 65 72 5c [0-15] 5c 52 65 6c 65 61 73 65 5c [0-15] 2e 70 64 62}  //weight: 1, accuracy: Low
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DL_2147807969_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DL!MTB"
        threat_id = "2147807969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 45 dc c7 04 24 00 00 00 00 c7 44 24 04 00 a3 e1 11 c7 44 24 08 00 30 00 00 c7 44 24 0c 04 00 00 00 89 4d d8 ff 55 dc}  //weight: 5, accuracy: High
        $x_1_2 = {89 f9 29 f1 88 0d ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? c1 fe 02 0f b6 3d ?? ?? ?? ?? c1 e7 06 89 f1 09 f9 88 0d ?? ?? ?? ?? 0f b6 35 13 00 88 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f b6 3d}  //weight: 1, accuracy: Low
        $x_1_3 = {89 f9 31 f1 88 0d ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? c1 fe 02 0f b6 3d ?? ?? ?? ?? c1 e7 06 89 f1 09 f9 88 0d ?? ?? ?? ?? 0f b6 35 13 00 88 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f b6 3d}  //weight: 1, accuracy: Low
        $x_1_4 = {89 f9 01 f1 88 0d ?? ?? ?? ?? 0f b6 35 ?? ?? ?? ?? c1 fe 05 0f b6 3d ?? ?? ?? ?? c1 e7 03 89 f1 09 f9 88 0d ?? ?? ?? ?? 0f b6 35 13 00 88 0d ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 0f b6 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_DM_2147809866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DM!MTB"
        threat_id = "2147809866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 c4 12 00 00 74 ?? 04 d2 34 b8 fe c0 fe c0 34 6a fe c8 04 99 34 7e 2c f2 2c d8 fe c8 fe c8 88 84 0d ?? ?? ?? ?? 83 c1 01 eb 07 00 8a 84 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DN_2147809933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DN!MTB"
        threat_id = "2147809933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 c8 12 00 00 74 ?? 04 69 04 27 fe c8 2c 46 34 a4 2c 55 2c f4 fe c0 fe c8 fe c0 2c c9 fe c0 fe c0 2c bf 88 84 0d ?? ?? ?? ?? 83 c1 01 eb 07 00 8a 84 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f9 e7 13 00 00 74 ?? fe c0 04 19 2c 5a 34 8b 04 30 fe c8 04 ef fe c8 04 c1 fe c8 fe c8 fe c8 34 72 2c 8b fe c8 fe c8 04 b9 04 76 88 84 0d ?? ?? ?? ?? 83 c1 01 eb 07 00 8a 84 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NSISInject_DO_2147810028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DO!MTB"
        threat_id = "2147810028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 b5 14 00 00 74 ?? fe c0 fe c8 fe c0 fe c8 04 4c fe c8 04 46 fe c0 fe c8 fe c0 34 97 2c ae fe c0 fe c0 04 2d 2c f1 34 f2 fe c8 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f9 d2 12 00 00 74 ?? fe c8 04 86 fe c0 fe c8 fe c8 fe c8 fe c0 04 76 fe c8 fe c0 34 ab 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {81 f9 01 13 00 00 74 ?? 2c a2 34 e5 fe c8 fe c0 fe c0 fe c0 fe c8 fe c8 fe c0 fe c0 2c 5e fe c8 34 3c 04 de fe c0 04 6c 34 5b 34 f5 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f9 40 14 00 00 74 ?? fe c8 fe c8 04 43 04 e5 fe c8 2c 10 fe c8 34 41 fe c0 34 9b 2c 68 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_5 = {81 f9 7d 14 00 00 74 ?? 2c 4e fe c0 2c d5 fe c0 fe c0 fe c8 04 1e fe c0 fe c8 34 f2 2c 6a fe c0 04 02 2c 7e 04 f5 fe c0 34 28 fe c8 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_6 = {81 f9 b2 12 00 00 74 ?? 04 38 fe c0 04 8a fe c8 2c fe fe c8 34 61 34 f7 2c e9 34 37 34 45 2c 4f fe c8 fe c8 fe c8 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_7 = {81 f9 e8 12 00 00 74 ?? 04 10 34 e3 34 f5 04 14 04 05 2c df 34 2f fe c0 fe c0 fe c0 fe c8 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_8 = {81 f9 26 15 00 00 74 ?? 34 26 fe c8 04 f8 2c de 2c 1e 2c 06 34 d2 04 a6 04 7a fe c0 fe c0 fe c8 fe c0 fe c0 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NSISInject_DP_2147810240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DP!MTB"
        threat_id = "2147810240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 9a 13 00 00 74 ?? fe c8 fe c8 fe c0 04 50 04 ed fe c8 fe c0 2c ce 2c 42 34 cd 04 9d 34 f1 34 25 fe c8 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {81 f9 45 14 00 00 74 ?? fe c0 04 8a 04 b7 fe c8 34 63 fe c8 2c 51 fe c0 2c 33 34 87 fe c0 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_3 = {81 f9 78 12 00 00 74 ?? 2c 94 34 ef 2c 0d 2c 54 fe c8 04 4e 2c 4c 2c 77 fe c0 2c 40 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
        $x_1_4 = {81 f9 e6 14 00 00 74 ?? 2c b3 34 ec fe c0 2c 17 fe c0 2c a4 04 2d 04 f3 34 a6 04 07 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NSISInject_DR_2147810572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DR!MTB"
        threat_id = "2147810572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 c2 13 00 00 74 ?? fe c0 fe c8 fe c0 2c 16 04 06 34 ff fe c0 fe c0 04 80 2c a6 34 67 2c c6 04 78 fe c8 34 e7 88 84 0d ?? ?? ?? ?? 83 c1 01 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DS_2147811611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DS!MTB"
        threat_id = "2147811611"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f9 0c 13 00 00 74 ?? fe c8 fe c0 fe c8 fe c0 fe c0 fe c0 2c 70 fe c8 04 cd 04 c7 04 a0 34 4b 2c 99 fe c8 fe c0 fe c0 fe c0 88 84 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DT_2147811612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DT!MTB"
        threat_id = "2147811612"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b 45 f4 50 6a 00 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4d f8 03 4d fc 0f b6 11 83 ea 4f 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 ea 01 8b 45 f8 03 45 fc 88 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DU_2147811691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DU!MTB"
        threat_id = "2147811691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c9 85 db 74 ?? 8a 04 39 2c 49 34 48 2c 32 34 b6 88 04 39 41 3b cb 72}  //weight: 1, accuracy: Low
        $x_1_2 = {33 c9 85 db 74 ?? 8a 04 39 04 6f 34 a7 2c 79 34 38 04 3a 88 04 39 41 3b cb 72}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c9 85 db 74 ?? 8a 04 39 2c 14 34 fd 04 6a 34 a4 fe c0 34 19 88 04 39 41 3b cb 72}  //weight: 1, accuracy: Low
        $x_1_4 = {33 c9 85 db 74 ?? 8a 04 39 2c 57 34 78 04 0c 34 b7 fe c0 34 1d 2c 02 88 04 39 41 3b cb 72}  //weight: 1, accuracy: Low
        $x_1_5 = {33 c9 85 db 74 ?? 8a 04 39 2c 62 34 1f 2c 08 34 9f fe c0 34 10 2c 3b 88 04 39 41 3b cb 72}  //weight: 1, accuracy: Low
        $x_1_6 = {33 c9 85 db 74 ?? 8a 04 39 04 19 34 9b 2c 39 34 86 2c 05 88 04 39 41 3b cb 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NSISInject_DV_2147811907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DV!MTB"
        threat_id = "2147811907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 45 f4 6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {8a 02 04 01 8b 4d f8 03 4d fc 88 01 8b 55 f8 03 55 fc 0f b6 02 83 f0 0d 8b 4d f8 03 4d fc 88 01}  //weight: 1, accuracy: High
        $x_1_3 = {0f b6 02 83 f0 69 8b 4d f8 03 4d fc 88 01 8b 55 f8 03 55 fc 0f b6 02 83 f0 64 8b 4d f8 03 4d fc 88 01}  //weight: 1, accuracy: High
        $x_1_4 = {8a 02 04 01 8b 4d f8 03 4d fc 88 01 8b 55 f8 03 55 fc 0f b6 02 83 c0 0e 8b 4d f8 03 4d fc 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_DW_2147812920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DW!MTB"
        threat_id = "2147812920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b d8 53 6a 00 ff d7}  //weight: 5, accuracy: High
        $x_1_2 = {8a 04 39 34 65 fe c8 34 49 fe c8 34 a1 04 10 88 04 39 41 3b cb 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DX_2147813042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DX!MTB"
        threat_id = "2147813042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {8b 4d f8 03 4d fc 88 01 e9 ?? ?? ff ff 8b 45 f8 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DY_2147813045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DY!MTB"
        threat_id = "2147813045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {8b 4d f8 03 4d fc 88 01 e9 ?? ?? ?? ?? 6a 00 6a 00 8b 55 f8 52 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_DZ_2147813649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.DZ!MTB"
        threat_id = "2147813649"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b 55 f4 52 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {8b 55 f8 03 55 fc 88 0a e9 ?? ?? ?? ?? 6a 00 6a 00 8b 45 f8 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EA_2147813659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EA!MTB"
        threat_id = "2147813659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? f7 d0 81 ea 1f 96 00 00 81 eb cd 16 01 00 bb c3 6c 00 00 35 96 24 01 00 f7 d2 43 59 c2}  //weight: 1, accuracy: Low
        $x_1_3 = {88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? 35 cd ce 00 00 81 e9 c2 fc 00 00 05 e9 5b 00 00 81 c2 24 c7 00 00 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_EB_2147813680_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EB!MTB"
        threat_id = "2147813680"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? 58 59 81 f2 30 09 00 00 2d 76 d6 00 00 05 0a 1a 00 00 43 c2}  //weight: 1, accuracy: Low
        $x_1_3 = {88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? 49 c2 ?? ?? 4a f7 d1 58 49 81 f3 b6 72 01 00 81 eb 1e 26 01 00 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_EC_2147813848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EC!MTB"
        threat_id = "2147813848"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? c2 ee 8c 43 f7 d0 5b 42 81 fa d2 ff 00 00 74 ?? c2 4b b6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_ED_2147813849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.ED!MTB"
        threat_id = "2147813849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 50 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {88 01 41 4e 75 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? 81 fb d9 58 00 00 74 0d c2 55 d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EE_2147813850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EE!MTB"
        threat_id = "2147813850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 50 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {88 01 41 4e 75 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? b9 9c c5 00 00 05 3f e4 00 00 81 f9 d3 b7 00 00 74}  //weight: 1, accuracy: Low
        $x_1_3 = {88 01 41 4e 75 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? f7 d1 81 eb f3 05 01 00 f7 d2 25 9d 35 00 00 c2 54 60}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_EF_2147813941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EF!MTB"
        threat_id = "2147813941"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b f0 56 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {88 04 39 41 3b ce 72 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EG_2147815402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EG!MTB"
        threat_id = "2147815402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b 45 f0 50 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {6a 00 6a 00 8b 55 f8 52 ff 15 ?? ?? ?? ?? 33 c0 8b e5 5d c3 07 00 88 01 e9 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EH_2147815508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EH!MTB"
        threat_id = "2147815508"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b f0 56 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {6a 40 68 00 30 00 00 8b 45 f0 50 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_5_3 = {6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_4 = {83 c1 10 3b ca 72 ?? 3b ce 73 [0-3] 80 04 39 ?? 41 3b ce 72 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c0 10 3b c2 72 ?? 3b c6 73 ?? 80 04 38 ?? 40 3b c6 72 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_6 = {88 0c 38 40 3b c6 72 ?? 6a 00 6a 00 57 ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f b6 11 83 f2 ?? 8b 45 f8 03 45 fc 88 10}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 4d f8 03 4d fc 88 01 8b 55 f8 03 55 fc 0f b6 02 35 [0-4] 8b 4d f8 03 4d fc 88 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_EI_2147815578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EI!MTB"
        threat_id = "2147815578"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b 45 f0 50 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {8b 4d f8 03 4d fc 88 01 e9 [0-4] 8b 45 f8 ff e0 33 c0 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EJ_2147815960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EJ!MTB"
        threat_id = "2147815960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 50 56 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {89 44 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 89 4d cc ff 15}  //weight: 5, accuracy: High
        $x_1_3 = {8b 75 f0 40 eb ?? 8b 45 f0 ff e0 c2 ce 3e 43 41 81 e2 d7 30 01 00 43 81 fb 5f 7a 01 00 74 ?? 81 f2 c8 e5 00 00 4a 81 f3 40 9c 00 00 ba ff 47 00 00 c2 1e 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {89 45 d8 e9 ?? ?? ff ff 8b 45 ec ff e0 83 c4 4c 5e 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_EL_2147816055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EL!MTB"
        threat_id = "2147816055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 50 53 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {8b 0c 24 80 ?? ?? ?? 40 39 c6 75 ?? 8b 04 24 ff e0 83 c4 0c 5e 5f 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EN_2147816227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EN!MTB"
        threat_id = "2147816227"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 54 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 89 4d c8 ff d0}  //weight: 5, accuracy: High
        $x_1_2 = {88 14 08 8b 45 d4 83 c0 01 89 45 d4 e9 ?? ?? ?? ?? 8b 45 e8 ff e0 83 c4 4c 5e 5f 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EK_2147816376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EK!MTB"
        threat_id = "2147816376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 50 57 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {6a 40 68 00 30 00 00 50 56 ff 15}  //weight: 5, accuracy: High
        $x_5_3 = {6a 40 68 00 30 00 00 50 53 ff 15}  //weight: 5, accuracy: High
        $x_10_4 = "NSIS Error" ascii //weight: 10
        $x_1_5 = {8b 3c 24 40 eb ?? 8b 04 24 ff e0 83 c4 0c 5e 5f 5b 5d c3 04 00 39 c5 74}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 75 f0 40 eb ?? 8b 45 f0 ff e0 81 f1 bd cb 00 00 4a 81 e3 2f e1 00 00 81 ea 51 57 00 00 c2 60 32 04 00 39 c3 74}  //weight: 1, accuracy: Low
        $x_1_7 = {40 39 c6 0f 85 ?? ?? ff ff 8b 04 24 ff e0 83 c4 0c 5e 5f 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_EM_2147816377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EM!MTB"
        threat_id = "2147816377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 50 53 ff 15}  //weight: 10, accuracy: High
        $x_10_2 = {6a 40 68 00 30 00 00 50 55 ff 15}  //weight: 10, accuracy: High
        $x_1_3 = {68 80 00 00 00 6a 03 ?? 6a 01 68 00 00 00 80 ff 70 04 ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = "GetCommandLineW" ascii //weight: 1
        $x_1_5 = "VirtualAlloc" ascii //weight: 1
        $x_1_6 = "CreateFileW" ascii //weight: 1
        $x_1_7 = "ReadFile" ascii //weight: 1
        $x_1_8 = "GetFileSize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_EO_2147816455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EO!MTB"
        threat_id = "2147816455"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 ff 75 f4 6a 00 ff 15}  //weight: 10, accuracy: High
        $x_1_2 = {68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 6a 04 58 c1 e0 00 8b 4d ec ff 34 01 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "GetCommandLineW" ascii //weight: 1
        $x_1_4 = "VirtualAlloc" ascii //weight: 1
        $x_1_5 = "CreateFileW" ascii //weight: 1
        $x_1_6 = "ReadFile" ascii //weight: 1
        $x_1_7 = "GetFileSize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EP_2147816477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EP!MTB"
        threat_id = "2147816477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 44 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 89 4d c8 ff 15}  //weight: 5, accuracy: High
        $x_1_2 = {88 14 08 8b 45 d4 83 c0 01 89 45 d4 e9 ?? ?? ?? ?? 8b 45 e8 ff e0 83 c4 4c 5e 5f 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EQ_2147816567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EQ!MTB"
        threat_id = "2147816567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b 55 f4 52 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {89 54 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 89 4d c4 ff d0}  //weight: 5, accuracy: High
        $x_1_3 = {8b 45 f8 03 45 fc [0-15] 8b 55 f8 03 55 fc 88 0a e9 ?? ?? ?? ?? 8b 45 f8 ff e0 8b e5 5d c2 10 00}  //weight: 1, accuracy: Low
        $x_1_4 = {88 14 08 8b 45 d0 83 c0 01 89 45 d0 e9 ?? ?? ?? ?? 8b 45 e8 ff e0 83 c4 50 5e 5f 5b 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_ER_2147816718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.ER!MTB"
        threat_id = "2147816718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b 45 f0 50 6a 00 ff 55}  //weight: 5, accuracy: High
        $x_5_2 = {89 54 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 89 4d b8 ff d0}  //weight: 5, accuracy: High
        $x_1_3 = {8b 4d f8 03 4d fc 0f b6 11 [0-6] 8b 45 f8 03 45 fc 88 10 e9 ?? ?? ?? ?? 8b 45 f8 ff e0 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {88 14 08 8b 45 d4 83 c0 01 89 45 d4 e9 ?? ?? ?? ?? 8b 45 e4 ff e0 83 c4 5c 5e 5f 5b 5d c2 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_ES_2147816915_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.ES!MTB"
        threat_id = "2147816915"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 50 57 ff 15}  //weight: 5, accuracy: High
        $x_5_2 = {6a 40 68 00 30 00 00 8b 55 f4 52 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_3 = {fe 04 01 8b 0c 24 80 04 01 ?? 39 c5 74 ?? 8b 3c 24 40 eb ?? 8b 04 24 ff e0 83 c4 0c 5e 5f 5b 5d c3}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 45 f8 03 45 fc 0f b6 08 [0-6] 8b 55 f8 03 55 fc 88 0a e9 ?? ?? ?? ?? 8b 45 f8 ff e0 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_SIBA_2147817061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SIBA!MTB"
        threat_id = "2147817061"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<program name unknown>" wide //weight: 1
        $x_1_2 = {88 0a 8b 45 ?? 03 45 ?? 8a 08 80 c1 ?? 8b 55 00 03 55 01 88 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {88 0a 8b 45 ?? 03 45 ?? 0f b6 08 83 f1 ?? 8b 55 00 03 55 01 88 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {88 0a 8b 45 ?? 03 45 ?? 0f b6 08 81 e9 ?? ?? ?? ?? 8b 55 00 03 55 01 88 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_ET_2147817457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.ET!MTB"
        threat_id = "2147817457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6a 40 68 00 30 00 00 8b 45 f0 50 6a 00 ff 55}  //weight: 5, accuracy: High
        $x_5_2 = {6a 40 68 00 30 00 00 8b 55 f4 52 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_5_3 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_5_4 = {6a 40 68 00 30 00 00 8b 55 ec 52 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_5_5 = {6a 40 68 00 30 00 00 8b 45 e8 50 6a 00 ff 15}  //weight: 5, accuracy: High
        $x_1_6 = {8b 4d f8 03 4d fc 8a 11 80 c2 01 8b 45 f8 03 45 fc 88 10 e9 ?? ?? ?? ?? 8b 45 f8 ff e0 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 45 f8 03 45 fc 8a 08 80 c1 01 8b 55 f8 03 55 fc 88 0a e9 ?? ?? ?? ?? 8b 45 f8 ff e0 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 55 f8 03 55 fc 0f b6 02 [0-6] 8b 4d f8 03 4d fc 88 01 e9 ?? ?? ?? ?? 8b 45 f8 ff e0 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 45 f8 03 45 fc 88 10 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 3b 55 ec 73 ?? e9 ?? ?? ?? ?? 8b 45 f8 ff e0 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_10 = {8b 4d f8 03 4d fc 0f b6 11 [0-6] 8b 45 f8 03 45 fc 88 10 e9 ?? ?? ?? ?? 8b 45 f8 ff e0 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_EV_2147817458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EV!MTB"
        threat_id = "2147817458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 50 6a 00 ff 15}  //weight: 10, accuracy: High
        $x_1_2 = {8b 14 24 80 04 0a ?? 8b 14 24 80 04 0a ?? 39 c8 74 ?? 8b 34 24 83 c1 01 eb ?? 8b 04 24 ff e0 83 c4 0c 5e 5f 5b c3}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 14 24 80 04 0a ?? 8b 14 24 80 04 0a ?? 83 c1 01 39 c8 0f 85 ?? ?? ?? ?? 8b 04 24 ff e0 83 c4 0c 5e 5f c3}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 14 24 80 34 0a ?? 8b 14 24 80 04 0a ?? 83 c1 01 39 c8 0f 85 ?? ?? ?? ?? 8b 04 24 ff e0 83 c4 0c 5e 5f c3}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 14 24 80 34 0a ?? 8b 14 24 80 34 0a ?? 39 c8 74 ?? 8b 34 24 83 c1 01 eb ?? 8b 04 24 ff e0 83 c4 0c 5e 5f 5b c3}  //weight: 1, accuracy: Low
        $x_1_6 = {8b 14 24 80 04 0a ?? 8b 14 24 80 34 0a ?? 83 c1 01 39 c8 0f 85 ?? ?? ?? ?? 8b 04 24 ff e0 83 c4 0c 5e 5f c3}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 14 24 80 04 0a ?? 8b 14 24 80 34 0a ?? 39 c8 74 ?? 8b 34 24 83 c1 01 eb ?? 8b 04 24 ff e0 83 c4 0c 5e 5f 5b c3}  //weight: 1, accuracy: Low
        $x_1_8 = {8b 14 24 80 34 0a ?? 8b 14 24 80 04 0a ?? 39 c8 74 ?? 8b 34 24 83 c1 01 eb ?? 8b 04 24 ff e0 83 c4 0c 5e 5f 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_EW_2147817811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EW!MTB"
        threat_id = "2147817811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 68 eb 12 00 00 56 ff 15}  //weight: 10, accuracy: High
        $x_1_2 = {88 04 33 46 81 fe eb 12 00 00 72 ?? 6a 00 53 6a 00 ff 15 ?? ?? ?? ?? 5f 5e 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EW_2147817811_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EW!MTB"
        threat_id = "2147817811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 08 89 c7 83 ec 10 66 0f 6f 05 00 20 40 00 f3 0f 7f 04 24 ff 15}  //weight: 10, accuracy: High
        $x_10_2 = {83 c4 08 89 c7 83 ec 10 0f 28 05 00 20 40 00 0f 11 04 24 ff 15}  //weight: 10, accuracy: High
        $x_10_3 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15}  //weight: 10, accuracy: High
        $x_1_4 = {6a 00 56 6a 00 ff 15 ?? ?? 40 00 83 c4 04 5e 5f c3 06 00 88 86}  //weight: 1, accuracy: Low
        $x_1_5 = {83 c0 20 3d f0 12 00 00 75 ?? 6a 00 56 6a 00 ff 15 ?? ?? 40 00 83 c4 04 5e 5f c3}  //weight: 1, accuracy: Low
        $x_1_6 = {60 14 00 00 6a 00 56 6a 00 ff 15 ?? ?? 40 00 83 c4 04 5e 5f c3}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 55 f8 03 55 fc 0f b6 02 [0-6] 8b 4d f8 03 4d fc 88 01 e9 [0-4] 8b 45 f8 ff e0 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_8 = {6a 00 56 6a 00 ff 15 ?? ?? 40 00 83 c4 04 5e 5f c3 07 00 0f 7f 8e}  //weight: 1, accuracy: Low
        $x_1_9 = {c1 f3 0f 7f ?? c0 13 00 00 6a 00 56 6a 00 ff 15 ?? ?? 40 00 83 c4 04 5e 5f c3}  //weight: 1, accuracy: Low
        $x_1_10 = {6a 00 56 6a 00 ff 15 ?? ?? 40 00 83 c4 04 5e 5f c3 06 00 88 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_NW_2147818112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.NW!MTB"
        threat_id = "2147818112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c4 08 89 45 ec 6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15 24 20 40 00}  //weight: 1, accuracy: High
        $x_1_2 = {52 6a 01 8b 45 f4 50 8b 4d f8 51 ff 15 30 20 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_NV_2147818183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.NV!MTB"
        threat_id = "2147818183"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b f8 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 56 ff 15 ?? 20 40 00}  //weight: 1, accuracy: Low
        $x_1_2 = {57 6a 01 8b d8 68 ?? ?? ?? ?? 53 ff 15 ?? 20 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_NX_2147818186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.NX!MTB"
        threat_id = "2147818186"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 8b f0 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 57 ff 15 30 20 40 00 56 6a 01 8b d8 68 ?? ?? ?? ?? 53 ff 15 50 20 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EX_2147818495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EX!MTB"
        threat_id = "2147818495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 08 8b f8 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 56 ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = {88 04 33 46 81 fe ?? ?? ?? ?? 72 ?? 6a 00 53 ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b 5d c2 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FA_2147818605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FA!MTB"
        threat_id = "2147818605"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b f8 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 56 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {83 c4 08 8b f0 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 57 ff 15}  //weight: 10, accuracy: Low
        $x_1_3 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_FB_2147818647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FB!MTB"
        threat_id = "2147818647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 0c 8b f0 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 57 ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = {88 04 3b 47 81 ff ?? ?? ?? ?? 72 ?? 6a 00 53 ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b 8b e5 5d c2 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EST_2147818902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EST!MTB"
        threat_id = "2147818902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 89 c7 83 ec 10 0f 28 05 00 20 40 00 0f 11 04 24 ff 15 ?? ?? ?? ?? 89 c6 57 6a 01 68 ?? ?? ?? ?? 50 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_ETC_2147819134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.ETC!MTB"
        threat_id = "2147819134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 53 6a 01 bb ?? ?? ?? ?? 8b f8 53 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FC_2147819218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FC!MTB"
        threat_id = "2147819218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 08 89 c7 83 ec 10 66 0f 6f 05 00 20 40 00 f3 0f 7f 04 24 ff 15}  //weight: 10, accuracy: High
        $x_1_2 = {13 00 00 6a 00 56 6a 00 ff 15 ?? ?? ?? ?? 83 c4 04 5e 5f c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_ESU_2147819236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.ESU!MTB"
        threat_id = "2147819236"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 59 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 57 8b f0 ff 15 ?? ?? ?? ?? 56 6a 01 be ?? ?? ?? ?? 8b d8 56 53 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_ETG_2147819254_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.ETG!MTB"
        threat_id = "2147819254"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 53 6a 01 bb ?? ?? ?? ?? 8b f8 53 57 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EZ_2147819303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EZ!MTB"
        threat_id = "2147819303"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 e8 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 50 ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = {8d 4d e4 51 50 ff 15 ?? ?? ?? ?? 31 f6 56 68 80 00 00 00 6a 03 56 6a 01 68 00 00 00 80 ff 70 04 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FE_2147819463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FE!MTB"
        threat_id = "2147819463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 04 68 00 30 00 00 68 80 74 d2 1a 56 ff d7}  //weight: 10, accuracy: High
        $x_1_2 = {46 3b f3 72 ?? 6a 00 57 ff 15 ?? ?? ?? ?? 81 c1 09 aa 00 00 b8 c2 b4 00 00 2d 0e 6b 01 00 f7 d1 81 f2 f9 a6 00 00 81 fb a8 4f 00 00 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FD_2147819571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FD!MTB"
        threat_id = "2147819571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15}  //weight: 10, accuracy: High
        $x_10_2 = {6a 40 68 00 30 00 00 8b 4d e8 51 6a 00 ff 15}  //weight: 10, accuracy: High
        $x_1_3 = {53 68 80 00 00 00 6a 03 53 6a 07 68 00 00 00 80 ff 75 10 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 b8 04 00 00 00 c1 e0 00 8b 4d e0 8b 14 01 52 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_FF_2147819603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FF!MTB"
        threat_id = "2147819603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 04 68 00 30 00 00 68 80 74 d2 1a 56 ff d7}  //weight: 10, accuracy: High
        $x_1_2 = {46 3b f3 72 ?? 6a 00 57 ff 15 ?? ?? ?? ?? 3d 2f e1 00 00 74 ?? f7 d2 81 c3 13 54 01 00 81 ea a7 27 01 00 c2 72 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_ETI_2147819731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.ETI!MTB"
        threat_id = "2147819731"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 59 59 6a 04 68 00 30 00 00 68 ?? ?? ?? ?? 56 ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 00 51 56 ff 75 e4 ff 34 18 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FH_2147819929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FH!MTB"
        threat_id = "2147819929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 04 68 00 30 00 00 68 80 74 d2 1a 57 ff d6}  //weight: 10, accuracy: High
        $x_1_2 = {88 04 3e 47 3b fb 72 ?? 6a 00 56 ff 15 ?? ?? ?? ?? 81 e9 14 c4 00 00 c2 2b 20}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AD_2147820154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AD!MTB"
        threat_id = "2147820154"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15 [0-4] 89 45 f8 8b 55 f0 52 6a 01 8b 45 f4 50 8b 4d f8 51 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f8 03 55 fc 8a 02 2c 01 8b 4d f8 03 4d fc 88 01 8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 f4 73 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FI_2147820217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FI!MTB"
        threat_id = "2147820217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15}  //weight: 10, accuracy: High
        $x_1_2 = {8b 4d f8 03 4d fc 88 01 8b 55 fc 83 c2 01 89 55 fc 8b 45 fc 3b 45 f4 73 ?? e9 ?? ?? ?? ?? 6a 00 8b 4d f8 51 ff 15 ?? ?? ?? ?? 33 c0 8b e5 5d c2 10 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EUM_2147820291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EUM!MTB"
        threat_id = "2147820291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 53 6a 01 8b f8 68 ?? ?? ?? ?? 57 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 0c 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 53 6a 01 bb ?? ?? ?? ?? 8b f0 53 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NSISInject_FK_2147820307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FK!MTB"
        threat_id = "2147820307"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d8 59 59 6a 04 68 00 30 00 00 68 80 74 d2 1a 57 ff d6}  //weight: 10, accuracy: High
        $x_1_2 = {88 04 3e 47 3b fb 72 ?? 6a 00 56 ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FL_2147820488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FL!MTB"
        threat_id = "2147820488"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c7 04 24 00 00 00 00 89 44 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15}  //weight: 10, accuracy: High
        $x_1_2 = {88 14 08 8b 45 f8 83 c0 01 89 45 f8 8b 45 f8 3b 45 f0 0f 83 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 45 f4 31 c9 89 04 24 c7 44 24 04 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 08 c7 45 fc 00 00 00 00 8b 45 fc 83 c4 34 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_EUG_2147822266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.EUG!MTB"
        threat_id = "2147822266"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 59 59 6a 04 68 00 30 00 00 68 ?? ?? ?? ?? 57 ff d6}  //weight: 1, accuracy: Low
        $x_1_2 = {53 6a 01 bb ?? ?? ?? ?? 8b f0 53 56 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AE_2147822345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AE!MTB"
        threat_id = "2147822345"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 6a 40 68 00 30 00 00 68 [0-4] 57 ff 15 [0-4] 56 6a 01 8b d8 68 b4 12 00 00 53 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 04 3b 2c ?? 34 ?? 04 ?? 34 ?? 04 ?? 34 ?? 04 ?? 34 ?? 88 04 3b 47 81 ff [0-4] 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BAD_2147826860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BAD!MTB"
        threat_id = "2147826860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "poweroff-vm-default.bat" wide //weight: 1
        $x_1_2 = "BatteryInfoView.exe" wide //weight: 1
        $x_1_3 = "Brugerordbogens.bib" wide //weight: 1
        $x_1_4 = "Temporary Internet Files\\REAGERENDES\\voldgiftsdomstolene\\Pigtail183\\Hofleverandr.lnk" wide //weight: 1
        $x_1_5 = "Start Menu\\Arundiferous\\Refurl\\Plasticlomme" wide //weight: 1
        $x_1_6 = "\\Kreditvrdige\\Olympiadevinderens\\Psalters.Som" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BAF_2147826861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BAF!MTB"
        threat_id = "2147826861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Storebededagsferiernes.exe" wide //weight: 1
        $x_1_2 = "Perimyelitis.ini" wide //weight: 1
        $x_1_3 = "Opgjorde.lnk" wide //weight: 1
        $x_1_4 = "Tnder.exe" wide //weight: 1
        $x_1_5 = "Maveondets212.exe" wide //weight: 1
        $x_1_6 = "Somatous.dll" wide //weight: 1
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Cockpitternes39" wide //weight: 1
        $x_1_8 = "Software\\Villaservitutter\\Hypostatize" wide //weight: 1
        $x_1_9 = "Software\\Kropslus146\\overlactated" wide //weight: 1
        $x_1_10 = "build\\release-x64\\tools-for-windows\\Win32\\services\\rvmSetup\\rvmSetup.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPF_2147827340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPF!MTB"
        threat_id = "2147827340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gydeplads166" ascii //weight: 1
        $x_1_2 = "Ragsokker\\Frimodighed.Rep" ascii //weight: 1
        $x_1_3 = "Storlinjedes\\Countertug.lnk" ascii //weight: 1
        $x_1_4 = "Sleepmarken\\Besmittendes.ini" ascii //weight: 1
        $x_1_5 = "Kuponklipperen" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPF_2147827340_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPF!MTB"
        threat_id = "2147827340"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Attributafhngighed.Ske" wide //weight: 1
        $x_1_2 = "Replicerer.Suk" wide //weight: 1
        $x_1_3 = "Boligministerier\\Poline\\Bisag.ini" wide //weight: 1
        $x_1_4 = "Lactase.Kob" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPI_2147827690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPI!MTB"
        threat_id = "2147827690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Wallowers\\Foranstillet155\\Retteprogrammernes14\\Pardhan" ascii //weight: 1
        $x_1_2 = "Stowey.Paa" ascii //weight: 1
        $x_1_3 = "Fortalendes" ascii //weight: 1
        $x_1_4 = "Sapidity.chi" ascii //weight: 1
        $x_1_5 = "Subangled.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPI_2147827690_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPI!MTB"
        threat_id = "2147827690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Aftener\\serrula" wide //weight: 1
        $x_1_2 = "Becolor\\Pericranium\\Scaut.Pht" wide //weight: 1
        $x_1_3 = "Ugennemsigtigheden\\Fixating\\Sabalos" wide //weight: 1
        $x_1_4 = "Adularescence\\Tudegrimt158" wide //weight: 1
        $x_1_5 = "Brickwise82.Glo" wide //weight: 1
        $x_1_6 = "Reasonablenesses" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FM_2147827930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FM!MTB"
        threat_id = "2147827930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Narkoernes\\Tilbagekbsvrdier.Eks" wide //weight: 1
        $x_1_2 = "\\Jujuism\\Frette.Jyt" wide //weight: 1
        $x_1_3 = "Software\\Circumoesophagal" wide //weight: 1
        $x_1_4 = "Prjudiciel" wide //weight: 1
        $x_1_5 = "Overtegnende" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FN_2147827931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FN!MTB"
        threat_id = "2147827931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Undoctor\\Plosions\\Orddelendes\\Degradable.mis" wide //weight: 1
        $x_1_2 = "Software\\Enfolden\\Fredningsnvn" wide //weight: 1
        $x_1_3 = "Software\\Faktoranalysernes\\zooid" wide //weight: 1
        $x_1_4 = "\\Miscreed\\pinochets\\Chef\\Tariferer.Aer" wide //weight: 1
        $x_1_5 = "Fabulists" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FO_2147828193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FO!MTB"
        threat_id = "2147828193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Frstegangsvlgere Setup" wide //weight: 1
        $x_1_2 = "Software\\Silicifluoric" wide //weight: 1
        $x_1_3 = "Toiletartiklerne" wide //weight: 1
        $x_1_4 = "\\Spirene79\\Spokespersons148.Sim" wide //weight: 1
        $x_1_5 = "fritnkersker" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FP_2147828194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FP!MTB"
        threat_id = "2147828194"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nringsmiddelets40\\Aspireringernes.Scr" wide //weight: 1
        $x_1_2 = "Svrvgtsklasses" wide //weight: 1
        $x_1_3 = "Software\\Bioteknikererne\\Ancerata" wide //weight: 1
        $x_1_4 = "Salrets" wide //weight: 1
        $x_1_5 = "gaberdine.Sce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RB_2147828802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RB!MTB"
        threat_id = "2147828802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 6a 0c 59 f7 f9 8b 45 bc 0f b6 04 10 8b 4d ec 03 4d f4 0f b6 09 33 c8 8b 45 ec 03 45 f4 88 08 eb cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RB_2147828802_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RB!MTB"
        threat_id = "2147828802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6a 40 68 00 30 00 00 68 00 09 3d 00 33 ff 57 ff d3 [0-32] 56 51 68 80 00 00 00 6a 03 51 6a 01 68 00 00 00 80 ff 75 10 ff 15 ?? ?? ?? ?? 8b f0 6a 00 56 ff 15 ?? ?? ?? ?? 6a 40 68 00 30 00 00 50 6a 00 89 45 fc ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RB_2147828802_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RB!MTB"
        threat_id = "2147828802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Greened150.ini" ascii //weight: 1
        $x_1_2 = "Billetkontors.Scy" ascii //weight: 1
        $x_1_3 = "Efterskriver.dll" ascii //weight: 1
        $x_1_4 = "Uninstall\\Thrashers" ascii //weight: 1
        $x_1_5 = "Outblaze\\misdistribute.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RB_2147828802_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RB!MTB"
        threat_id = "2147828802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Solbrmarmelades.Kur" ascii //weight: 1
        $x_1_2 = "Strunke.ini" ascii //weight: 1
        $x_1_3 = "Software\\Systemfunktionerne" ascii //weight: 1
        $x_1_4 = "Forbldningers\\Ratted.ini" ascii //weight: 1
        $x_1_5 = "Demokratiseret.Viz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RB_2147828802_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RB!MTB"
        threat_id = "2147828802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Melilites\\Tkket" ascii //weight: 1
        $x_1_2 = "Software\\misfortolkningens" ascii //weight: 1
        $x_1_3 = "Expirer.ini" ascii //weight: 1
        $x_1_4 = "Livsfaren\\Chrilless.ini" ascii //weight: 1
        $x_1_5 = "Countershading.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RB_2147828802_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RB!MTB"
        threat_id = "2147828802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lsnings\\Politidirektrs" wide //weight: 1
        $x_1_2 = "Abrogated.dll" wide //weight: 1
        $x_1_3 = "Solfiltrene.Gar" wide //weight: 1
        $x_1_4 = "Software\\Rgskys\\vandbeholders" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RB_2147828802_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RB!MTB"
        threat_id = "2147828802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Uncontemptuously.Pro" wide //weight: 1
        $x_1_2 = "Magtkamp.uta" wide //weight: 1
        $x_1_3 = "Deliberations.Mic" wide //weight: 1
        $x_1_4 = "Lampadite.Wes" wide //weight: 1
        $x_1_5 = "Skandinaviseringernes69\\Frankie.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RB_2147828802_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RB!MTB"
        threat_id = "2147828802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Haler Sundogs Brewage" wide //weight: 1
        $x_1_2 = "Blancheredes" wide //weight: 1
        $x_1_3 = "Earthquake maris Gammen" wide //weight: 1
        $x_1_4 = "Fulminurate Zendo" wide //weight: 1
        $x_1_5 = "Preposed.exe" wide //weight: 1
        $x_1_6 = "Skurvogne Nonimpregnated" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPC_2147828831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPC!MTB"
        threat_id = "2147828831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Opridsning" ascii //weight: 1
        $x_1_2 = "Software\\Communisteries\\Masseskrivelsers\\Lejders\\Indkomstbeskattede" ascii //weight: 1
        $x_1_3 = "Heterogonously.Afl" ascii //weight: 1
        $x_1_4 = "Samtalepartners.Svu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPC_2147828831_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPC!MTB"
        threat_id = "2147828831"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Countermand.ini" wide //weight: 1
        $x_1_2 = "Smittleish.Kri2" wide //weight: 1
        $x_1_3 = "Galvanisk\\Oubliance.ini" wide //weight: 1
        $x_1_4 = "Slutstrrelsernes.Kam" wide //weight: 1
        $x_1_5 = "Swingpjatters.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPD_2147828832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPD!MTB"
        threat_id = "2147828832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mastooccipital33" ascii //weight: 1
        $x_1_2 = "Software\\Unbefringed" ascii //weight: 1
        $x_1_3 = "Primitivitet50.Kny255" ascii //weight: 1
        $x_1_4 = "Statsrettens29.Dis" ascii //weight: 1
        $x_1_5 = "Fragmenterende.Gte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPD_2147828832_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPD!MTB"
        threat_id = "2147828832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Kirkegaardsjordene\\Tru\\Donkeymndenes\\Paralyseringernes" ascii //weight: 1
        $x_1_2 = "Kayoing.dll" ascii //weight: 1
        $x_1_3 = "Venisonlike" ascii //weight: 1
        $x_1_4 = "Vandledningsafgifter" ascii //weight: 1
        $x_1_5 = "Trkkrogenes.Ass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPD_2147828832_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPD!MTB"
        threat_id = "2147828832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "udgivelsesdage.ini" ascii //weight: 1
        $x_1_2 = "Absorbancy.unp" ascii //weight: 1
        $x_1_3 = "Discoplacental.Uno" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Flsen\\Kattelems\\Myggens58" ascii //weight: 1
        $x_1_5 = "Spontanspillene.Pre" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPD_2147828832_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPD!MTB"
        threat_id = "2147828832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Climax\\Rigers.ini" wide //weight: 1
        $x_1_2 = "Recirkulerendes.ini" wide //weight: 1
        $x_1_3 = "dreks.lnk" wide //weight: 1
        $x_1_4 = "Anpartskapitalens.Biz" wide //weight: 1
        $x_1_5 = "Corrasion.tho" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPK_2147829241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPK!MTB"
        threat_id = "2147829241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Buol\\arithmetic.ini" ascii //weight: 1
        $x_1_2 = "sideboard\\genotoxicity.bin" ascii //weight: 1
        $x_1_3 = "markerboard\\secretaire\\acceptant.txt" ascii //weight: 1
        $x_1_4 = "faceless.docx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPK_2147829241_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPK!MTB"
        threat_id = "2147829241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Parasitterne" ascii //weight: 1
        $x_1_2 = "Macabreness.Unh" ascii //weight: 1
        $x_1_3 = "Aktieuroen\\Sophisticalness\\Forretningsordens.dll" ascii //weight: 1
        $x_1_4 = "Galactopyranoside.lnk" ascii //weight: 1
        $x_1_5 = "Hits47.Til" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPL_2147829242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPL!MTB"
        threat_id = "2147829242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Talelidelsernes\\Ciceronian\\Standkister" ascii //weight: 1
        $x_1_2 = "Software\\Nonobviousness\\Transship\\laurbrkransen" ascii //weight: 1
        $x_1_3 = "Rentebelbene.Hem" ascii //weight: 1
        $x_1_4 = "Derouters.lnk" ascii //weight: 1
        $x_1_5 = "Riksdaalder.Bol" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPN_2147829684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPN!MTB"
        threat_id = "2147829684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Deerskin" ascii //weight: 1
        $x_1_2 = "Byfornyelsernes.For" ascii //weight: 1
        $x_1_3 = "Software\\Nonoligarchical\\raids\\Trillingefdsel" ascii //weight: 1
        $x_1_4 = "Travetures.ini" ascii //weight: 1
        $x_1_5 = "Fluidums.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPO_2147829685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPO!MTB"
        threat_id = "2147829685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f0 38 88 45 ff 0f b6 4d ff 2b 4d f8 88 4d ff 0f b6 55 ff 81 f2 ac 00 00 00 88 55 ff 0f b6 45 ff f7 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPO_2147829685_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPO!MTB"
        threat_id = "2147829685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Spondylus.Rei" ascii //weight: 1
        $x_1_2 = "Holocentrid.Stu" ascii //weight: 1
        $x_1_3 = "Regelfaststtelsernes.dll" ascii //weight: 1
        $x_1_4 = "Hypnotherapist50.Non" ascii //weight: 1
        $x_1_5 = "Microgamy\\Bekldt.Bus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPO_2147829685_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPO!MTB"
        threat_id = "2147829685"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stadsingeniren" wide //weight: 1
        $x_1_2 = "Chartres141" wide //weight: 1
        $x_1_3 = "Software\\slaraffenliv\\Oveni\\Forsyner\\Glattedes" wide //weight: 1
        $x_1_4 = "Landsherrens.ini" wide //weight: 1
        $x_1_5 = "Crowfooted.Aft" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPP_2147829686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPP!MTB"
        threat_id = "2147829686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Deponeringsmulighed" ascii //weight: 1
        $x_1_2 = "Bludge\\Nonspinose170\\Nominatival80.ini" ascii //weight: 1
        $x_1_3 = "Boweryish221.lnk" ascii //weight: 1
        $x_1_4 = "Cadwal.Rei" ascii //weight: 1
        $x_1_5 = "Delighter.Ing45" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPP_2147829686_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPP!MTB"
        threat_id = "2147829686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ballepresserne" ascii //weight: 1
        $x_1_2 = "Software\\Duelighedstegn\\Andenprmies\\Rabbinaternes" ascii //weight: 1
        $x_1_3 = "Oversensitivity14" ascii //weight: 1
        $x_1_4 = "Gldesskrig174.Omk" ascii //weight: 1
        $x_1_5 = "Overpunched.Bar" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPP_2147829686_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPP!MTB"
        threat_id = "2147829686"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stjsikkert\\Couriers" wide //weight: 1
        $x_1_2 = "Drollish.ads" wide //weight: 1
        $x_1_3 = "Antipsalmist.Fir" wide //weight: 1
        $x_1_4 = "Software\\Antimaniacal\\Bogladeprisens\\Inadvisability" wide //weight: 1
        $x_1_5 = "Ampere.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPQ_2147829687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPQ!MTB"
        threat_id = "2147829687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Scatterable\\Boogymen" ascii //weight: 1
        $x_1_2 = "Teoretiseringen" ascii //weight: 1
        $x_1_3 = "Software\\Environmentalist30\\Saturating" ascii //weight: 1
        $x_1_4 = "Siderite" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPQ_2147829687_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPQ!MTB"
        threat_id = "2147829687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Congii" ascii //weight: 1
        $x_1_2 = "Necktieless" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\afmagringerne" ascii //weight: 1
        $x_1_4 = "Appelmuligheder.Ozo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPQ_2147829687_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPQ!MTB"
        threat_id = "2147829687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Civilbefolkning" wide //weight: 1
        $x_1_2 = "Software\\Ubehagelige" wide //weight: 1
        $x_1_3 = "Brattingsborgs" wide //weight: 1
        $x_1_4 = "Anneloid.Ace" wide //weight: 1
        $x_1_5 = "Monorhina.ste" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPQ_2147829687_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPQ!MTB"
        threat_id = "2147829687"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Parasitterne" wide //weight: 1
        $x_1_2 = "Bisamrottes.Tin" wide //weight: 1
        $x_1_3 = "Forretningsordens.dll" wide //weight: 1
        $x_1_4 = "Galactopyranoside.lnk" wide //weight: 1
        $x_1_5 = "Software\\Opfinderprisernes\\Colourableness\\Tyvstjlende\\Tosily" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPR_2147829710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPR!MTB"
        threat_id = "2147829710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Coequalizes" wide //weight: 1
        $x_1_2 = "Fondskodeskiftet" wide //weight: 1
        $x_1_3 = "Dadaistically.Ano" wide //weight: 1
        $x_1_4 = "Forskrifts.dll" wide //weight: 1
        $x_1_5 = "Engblommens170.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPR_2147829710_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPR!MTB"
        threat_id = "2147829710"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Talerstolens" wide //weight: 1
        $x_1_2 = "Haceks.Pla" wide //weight: 1
        $x_1_3 = "Rejsemontrs.Gra" wide //weight: 1
        $x_1_4 = "Tennisketsjerne\\Medicinaldirektrerne\\Trichoglossidae\\Kofeminismernes.ini" wide //weight: 1
        $x_1_5 = "Vegetomineral.Ste" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPM_2147829759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPM!MTB"
        threat_id = "2147829759"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Anlgsinvesteringer.Min" ascii //weight: 1
        $x_1_2 = "Abelsk.Hum" ascii //weight: 1
        $x_1_3 = "Software\\Cholecystectasia89\\Pepysian\\Nonpestilently" ascii //weight: 1
        $x_1_4 = "Samleobjekts.ini" ascii //weight: 1
        $x_1_5 = "Indebt.Bes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RC_2147830040_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RC!MTB"
        threat_id = "2147830040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 [0-149] c7 44 24 10 03 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 18 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 1c 89 85 48 fe ff ff 8b 85 48 fe ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RC_2147830040_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RC!MTB"
        threat_id = "2147830040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 [0-101] 89 04 24 c7 44 24 04 00 00 00 80 c7 44 24 08 01 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 18 00 00 00 00 ff 15 ?? ?? ?? ?? 83 ec 1c 89 45 b0 8b 45 b0 31 c9 89 04 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RC_2147830040_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RC!MTB"
        threat_id = "2147830040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Underforstaaet.ini" ascii //weight: 1
        $x_1_2 = "Tvrstillede.ini" ascii //weight: 1
        $x_1_3 = "majoriseringens.Nyn" ascii //weight: 1
        $x_1_4 = "Mettes.Sig" ascii //weight: 1
        $x_1_5 = "Tusindets.lnk" ascii //weight: 1
        $x_1_6 = "Ailuromania.Ner" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RC_2147830040_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RC!MTB"
        threat_id = "2147830040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mikroskopere.lnk" ascii //weight: 1
        $x_1_2 = "Skumslukkeren.ini" ascii //weight: 1
        $x_1_3 = "Persisk.lnk" ascii //weight: 1
        $x_1_4 = "raffinaderiprodukts.ini" ascii //weight: 1
        $x_1_5 = "Columnizing.dll" ascii //weight: 1
        $x_1_6 = "solingklassernes.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_NSISInject_RC_2147830040_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RC!MTB"
        threat_id = "2147830040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kolonner1.ini" wide //weight: 1
        $x_1_2 = "Krystaller\\Voldenes.Hai" wide //weight: 1
        $x_1_3 = "erremanden.For" wide //weight: 1
        $x_1_4 = "Glamourless.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RC_2147830040_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RC!MTB"
        threat_id = "2147830040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Linoleummets.lnk" wide //weight: 1
        $x_1_2 = "Markedsandelen83.ini" wide //weight: 1
        $x_1_3 = "produktionsforhold.Glo" wide //weight: 1
        $x_1_4 = "face-monkey.png" wide //weight: 1
        $x_1_5 = "Ultraritualism.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RC_2147830040_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RC!MTB"
        threat_id = "2147830040"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "symbolography projektionens leopardine" wide //weight: 1
        $x_1_2 = "startgt krybskytterne.exe" wide //weight: 1
        $x_1_3 = "tuberose ivrkstterens stvletramps" wide //weight: 1
        $x_1_4 = "dispapalize kreaturet paliurus" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FQ_2147830167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FQ!MTB"
        threat_id = "2147830167"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Forsvarschefs\\Relikvieskrinets.ini" ascii //weight: 1
        $x_1_2 = "Nskeforestillingers" ascii //weight: 1
        $x_1_3 = "Software\\Styraxes\\Italicising" ascii //weight: 1
        $x_1_4 = "\\klamreaben\\trykkogerne\\Ligningernes" ascii //weight: 1
        $x_1_5 = "Glacialize130.Uge" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FR_2147830168_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FR!MTB"
        threat_id = "2147830168"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Statsretten" ascii //weight: 1
        $x_1_2 = "Comparate.Chu153" ascii //weight: 1
        $x_1_3 = "Software\\wetness\\Knuselskes" ascii //weight: 1
        $x_1_4 = "Sygeforsikrings" ascii //weight: 1
        $x_1_5 = "Software\\Talblokken\\prettiest" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FS_2147830169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FS!MTB"
        threat_id = "2147830169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Beslagsmedenes\\Agpaitic\\Luftfartjernes" ascii //weight: 1
        $x_1_2 = "Software\\Stjkortlgningens" ascii //weight: 1
        $x_1_3 = "\\Caleb62\\Cancellous.Una" ascii //weight: 1
        $x_1_4 = "\\bnskriftet\\Tekstanmrkningers.Hem" ascii //weight: 1
        $x_1_5 = "\\Fastrenes\\facaders.Fil" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPB_2147830185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPB!MTB"
        threat_id = "2147830185"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lithonephria" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\dacelonine" wide //weight: 1
        $x_1_3 = "enkepensionist.Rep" wide //weight: 1
        $x_1_4 = "Software\\Chkfile47\\Simuleringen\\Leis\\Lamellose" wide //weight: 1
        $x_1_5 = "Confectory.Det" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RE_2147830302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RE!MTB"
        threat_id = "2147830302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 b9 0c 00 00 00 f7 f9 8b 45 e0 0f b6 0c 10 8b 55 cc 03 55 fc 0f b6 02 33 c1 8b 4d cc 03 4d fc 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RE_2147830302_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RE!MTB"
        threat_id = "2147830302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 e7 d1 ea 83 e2 fc 8d 04 52 89 ca 29 c2 0f b6 92 ?? ?? ?? ?? 30 14 0e f7 d8 0f b6 84 01 ?? ?? ?? ?? 30 44 0e 01 83 c1 02 39 cb 75 d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RE_2147830302_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RE!MTB"
        threat_id = "2147830302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 80 00 00 6a 32 89 44 24 ?? ff d6 50 6a 31 ff d6 50 33 f6 46 56 57}  //weight: 1, accuracy: Low
        $x_1_2 = {50 c7 45 a8 58 00 00 00 c7 45 b4 ?? ?? ?? ?? c7 45 dc 66 08 88 00 c7 45 ec ?? ?? ?? ?? c7 45 f0 ?? 01 00 00 c7 45 e4 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RE_2147830302_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RE!MTB"
        threat_id = "2147830302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mynderne159\\Atrichic.ini" ascii //weight: 1
        $x_1_2 = "Rhymes112.ini" ascii //weight: 1
        $x_1_3 = "Software\\Creosols" ascii //weight: 1
        $x_1_4 = "Software\\Klusilens" ascii //weight: 1
        $x_1_5 = "Brndingers.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RE_2147830302_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RE!MTB"
        threat_id = "2147830302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Trakeotomis" ascii //weight: 1
        $x_1_2 = "Veniremen.ini" ascii //weight: 1
        $x_1_3 = "Endosserings\\Skrferes.ini" ascii //weight: 1
        $x_1_4 = "Caretta.Scr" ascii //weight: 1
        $x_1_5 = "Uninstall\\Fallalishly" ascii //weight: 1
        $x_1_6 = "Navigationsskoler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RE_2147830302_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RE!MTB"
        threat_id = "2147830302"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Untrading.ini" ascii //weight: 1
        $x_1_2 = "Writeoffs.Beq" ascii //weight: 1
        $x_1_3 = "Software\\Humistratous" ascii //weight: 1
        $x_1_4 = "Analyseperioderne143.Eft" ascii //weight: 1
        $x_1_5 = "Helbroderen.lnk" ascii //weight: 1
        $x_1_6 = "Aristokratiske.Dde" ascii //weight: 1
        $x_1_7 = "Afskrivningsmulighederne.Bed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPJ_2147830430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPJ!MTB"
        threat_id = "2147830430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Gyroidal\\Telefonannoncen\\Spiseolier" ascii //weight: 1
        $x_1_2 = "Hematinic" ascii //weight: 1
        $x_1_3 = "Rhett.ini" ascii //weight: 1
        $x_1_4 = "Forsnakkelse" ascii //weight: 1
        $x_1_5 = "Skovvsner.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPJ_2147830430_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPJ!MTB"
        threat_id = "2147830430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Plasmaphereses" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Alleys\\Diporpa" ascii //weight: 1
        $x_1_3 = "Ekstraafgift.lnk" ascii //weight: 1
        $x_1_4 = "Efterrationaliserings.Pre" ascii //weight: 1
        $x_1_5 = "Macroseismograph.Dds" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPJ_2147830430_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPJ!MTB"
        threat_id = "2147830430"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Propending177.fea" wide //weight: 1
        $x_1_2 = "shantytown.non" wide //weight: 1
        $x_1_3 = "Japhetide.lnk" wide //weight: 1
        $x_1_4 = "Software\\Flangers\\Datakopierings\\Skabsgangenes" wide //weight: 1
        $x_1_5 = "Oversoothingly.esr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPV_2147831113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPV!MTB"
        threat_id = "2147831113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Scrumption" ascii //weight: 1
        $x_1_2 = "Ellipsoiderne114.Byd" ascii //weight: 1
        $x_1_3 = "Enkeltheder.ini" ascii //weight: 1
        $x_1_4 = "Ugennemfrlighedens246.lnk" ascii //weight: 1
        $x_1_5 = "Noctambulistic.Pal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPE_2147831300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPE!MTB"
        threat_id = "2147831300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "20.254.53.47/brume.php" ascii //weight: 1
        $x_1_2 = "20.234.231.114/mx/j57b5g9s8tr58cwm0ppp" ascii //weight: 1
        $x_1_3 = "pifeaizgjc.hda" ascii //weight: 1
        $x_1_4 = "e6744b46lf94b86re1cooo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPE_2147831300_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPE!MTB"
        threat_id = "2147831300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Elektronikindustrien" ascii //weight: 1
        $x_1_2 = "Uderummenes.Ste" ascii //weight: 1
        $x_1_3 = "Komtok.Ope" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\retirant\\Adresselisten" ascii //weight: 1
        $x_1_5 = "Indtagningens.Une" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AF_2147831526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AF!MTB"
        threat_id = "2147831526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bicolored\\pedipulate\\bergensere.ini" wide //weight: 1
        $x_1_2 = "Diaboleptic\\Tidndens\\Tragicomicality\\Forgafler.Vis" wide //weight: 1
        $x_1_3 = "chiapas\\Elius\\Pliable.Cow" wide //weight: 1
        $x_1_4 = "Unappreciativeness.Udg" wide //weight: 1
        $x_1_5 = "Spaders\\Pisolitic214.ini" wide //weight: 1
        $x_1_6 = "Thievishly\\Cryptographal\\Monobasicity\\Bh127" wide //weight: 1
        $x_1_7 = "Recepisser\\vaadomraadernes\\Octonal243.For" wide //weight: 1
        $x_1_8 = "Hvislendes.Eks" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPG_2147831533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPG!MTB"
        threat_id = "2147831533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Urbanitetens" ascii //weight: 1
        $x_1_2 = "Ggelederne.Avl240" ascii //weight: 1
        $x_1_3 = "Software\\Coercive\\Lorarius\\Hoisted" ascii //weight: 1
        $x_1_4 = "Bioteknikerernes.Jun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPG_2147831533_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPG!MTB"
        threat_id = "2147831533"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ferrimagnetically" ascii //weight: 1
        $x_1_2 = "Software\\Disorderer\\Medlemslister\\Peascod" ascii //weight: 1
        $x_1_3 = "Banjos.Bev" ascii //weight: 1
        $x_1_4 = "Foldningsstningerne" ascii //weight: 1
        $x_1_5 = "outspent.Rot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AG_2147831783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AG!MTB"
        threat_id = "2147831783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Poneridae\\Suberin.ini" ascii //weight: 1
        $x_1_2 = "%WINDIR%\\kommentarfacilitet\\Rendzinas.Sup" ascii //weight: 1
        $x_1_3 = "Voltere\\Geogonical.ini" ascii //weight: 1
        $x_1_4 = "implicativeness\\Picklock\\Udgiftsbehovets\\Differentialligningssystemernes.Kul" ascii //weight: 1
        $x_1_5 = "cain\\Ductileness.Pia" ascii //weight: 1
        $x_1_6 = "Guiltful\\Frysebokse" ascii //weight: 1
        $x_1_7 = "Skarabens\\Skibsdrengene92\\Brighting\\Swedger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RA_2147831788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RA!MTB"
        threat_id = "2147831788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 9d b8 f4 ff ff 0f af 9d 0c f5 ff ff 8b 45 14 8b 08 03 8d 18 f5 ff ff 0f be 71 04 03 de 0f be 95 10 f5 ff ff 2b da 89 9d b8 f4 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RA_2147831788_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RA!MTB"
        threat_id = "2147831788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 40 89 45 f4 8b 45 f4 3b 45 e0 73 25 8b 45 f4 99 6a 0c 59 f7 f9 8b 45 e4 0f b6 04 10 8b 4d dc 03 4d f4 0f b6 09 33 c8 8b 45 dc 03 45 f4 88 08 eb cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RA_2147831788_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RA!MTB"
        threat_id = "2147831788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Nonregardance" wide //weight: 1
        $x_1_2 = "Troupials\\Aggressive.ini" wide //weight: 1
        $x_1_3 = "Software\\Recreancy" wide //weight: 1
        $x_1_4 = "Forivredes\\Rigtigtnok.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AH_2147832022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AH!MTB"
        threat_id = "2147832022"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Fripasset\\Forhandlingsgrundlagenes\\pastaerne" wide //weight: 1
        $x_1_2 = "Ligkapels\\Acromonogrammatic\\Psychogram.lnk" wide //weight: 1
        $x_1_3 = "Fysiklreres\\Coinmaking\\Orthodoxicalness.ini" wide //weight: 1
        $x_1_4 = "Lymphography\\Totaktere\\Anionically185.ini" wide //weight: 1
        $x_1_5 = "billigeres\\Tittupped\\pugnacious.Uno" wide //weight: 1
        $x_1_6 = "Polymetameric\\Uerholdelige\\Dvrgtrers.Mal" wide //weight: 1
        $x_1_7 = "Vagabondize\\Rosalinde\\Tonefaldets.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPS_2147832126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPS!MTB"
        threat_id = "2147832126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tjanting.Men" ascii //weight: 1
        $x_1_2 = "Coenoblastic.ini" ascii //weight: 1
        $x_1_3 = "Bourbonist39" ascii //weight: 1
        $x_1_4 = "Software\\Titterers\\Sanjakbeg\\Olieforurenendes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPS_2147832126_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPS!MTB"
        threat_id = "2147832126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Terminableness73.lnk" ascii //weight: 1
        $x_1_2 = "baggrundsperioder" ascii //weight: 1
        $x_1_3 = "Termograferings" ascii //weight: 1
        $x_1_4 = "Fyldningernes.ini" ascii //weight: 1
        $x_1_5 = "Software\\Bagsderyglnenes\\Motionen\\Floter116\\Antologier" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPA_2147832367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPA!MTB"
        threat_id = "2147832367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Strikketjet" ascii //weight: 1
        $x_1_2 = "Bottomer.Cax228" ascii //weight: 1
        $x_1_3 = "Dybfrossen.ini" ascii //weight: 1
        $x_1_4 = "beneficing\\Galahads.Sun" ascii //weight: 1
        $x_1_5 = "Socialarbejde.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPA_2147832367_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPA!MTB"
        threat_id = "2147832367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "caravaners" ascii //weight: 1
        $x_1_2 = "Unnotioned.bmp" ascii //weight: 1
        $x_1_3 = "Blaaligt" ascii //weight: 1
        $x_1_4 = "Schorlomite99" ascii //weight: 1
        $x_1_5 = "Software\\Bifurcation\\Wended\\Outcastes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RF_2147833574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RF!MTB"
        threat_id = "2147833574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 57 6a 00 ff [0-5] 56 6a 01 [0-32] b8 ab aa aa aa f7 e6 [0-3] c1 ea 03 [0-3] 8d 0c 52 c1 e1 02 2b c1 [0-2] 8a 80 ?? ?? ?? ?? 30 ?? 33 [0-3] 3b f7 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RF_2147833574_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RF!MTB"
        threat_id = "2147833574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Aggregatfunktionerne\\Subtext.Int" ascii //weight: 1
        $x_1_2 = "Multilaminated\\Warlockry.ini" ascii //weight: 1
        $x_1_3 = "Pitfalls\\Nikkede.ini" ascii //weight: 1
        $x_1_4 = "Bevidstheders\\Unred\\Thielo.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RF_2147833574_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RF!MTB"
        threat_id = "2147833574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sodavandsflaskers\\giannina\\orgels" wide //weight: 1
        $x_1_2 = "Susendes\\Scrumption" wide //weight: 1
        $x_1_3 = "Aesopian\\Understyr.Tei" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RF_2147833574_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RF!MTB"
        threat_id = "2147833574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 d2 89 0c 24 c7 44 24 04 00 00 00 80 c7 44 24 08 01 00 00 00 c7 44 24 0c 00 00 00 00 c7 44 24 10 03 00 00 00 c7 44 24 14 80 00 00 00 c7 44 24 18 00 00 00 00 ff d0 83 ec 1c 89 45 ?? b8 ff ff ff ff 39 45 [0-96] c7 04 24 00 00 00 00 89 ?? 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 3a 00 5c 00 78 00 61 00 6d 00 70 00 70 00 5c 00 68 00 74 00 64 00 6f 00 63 00 73 00 5c 00 [0-37] 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 5c 00 52 00 65 00 6c 00 65 00 61 00 73 00 65 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 70 00 64 00 62 00}  //weight: 1, accuracy: Low
        $x_1_3 = {43 3a 5c 78 61 6d 70 70 5c 68 74 64 6f 63 73 5c [0-37] 5c 4c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_NSISInject_FU_2147833691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FU!MTB"
        threat_id = "2147833691"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Thermodynamician Disquietingly Fornaegter" wide //weight: 1
        $x_1_2 = "Druggiest Specialomraadernes Bumsets" wide //weight: 1
        $x_1_3 = "Ritornel Outcast" wide //weight: 1
        $x_1_4 = "Svanesen Paalagte Kimono" wide //weight: 1
        $x_1_5 = "unknowndll.pdb" ascii //weight: 1
        $x_1_6 = "Grady" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FV_2147833943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FV!MTB"
        threat_id = "2147833943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Finesses\\Driftstabenes.mil" wide //weight: 1
        $x_1_2 = "Dkslets231\\Pergelisol\\Programudviklingernes\\Retare.Alm" wide //weight: 1
        $x_1_3 = "Software\\Umoralskhedens\\Udflder\\Skibsredere" wide //weight: 1
        $x_1_4 = "Recitator\\Gjalt\\Bogede\\memorere.Pup" wide //weight: 1
        $x_1_5 = "Extraversively\\Sammenkdningens.Leo171" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RD_2147833966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RD!MTB"
        threat_id = "2147833966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ab aa aa aa f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a ?? ?? ?? ?? ?? 30 14 0e 41 3b cf 72 dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RD_2147833966_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RD!MTB"
        threat_id = "2147833966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 ab aa aa aa f7 e6 8b c6 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 8a 80 ?? ?? ?? ?? 30 04 1e 46 3b f7 72 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RD_2147833966_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RD!MTB"
        threat_id = "2147833966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "dykkere\\Uninstall\\josiass" ascii //weight: 2
        $x_1_2 = "manifestationer\\betvivle.ini" ascii //weight: 1
        $x_1_3 = "\\Kulturforskelle\\programmr.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RD_2147833966_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RD!MTB"
        threat_id = "2147833966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c0 c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15 [0-53] 83 7d f4 00 0f 84 1d 00 00 00 8b 45 ec c6 00 00 8b 45 ec 83 c0 01 89 45 ec 8b 45 f4 83 c0 ff 89 45 f4 e9 d9 ff ff ff 8b 45 10 31 c9 89 04 24 c7 44 24 04 00 00 00 80 c7 44 24 08 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RD_2147833966_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RD!MTB"
        threat_id = "2147833966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Windows\\Fotoernes\\Uninstall\\Inhalatoren224" ascii //weight: 2
        $x_1_2 = "Farvebaandsomskifteren.txt" ascii //weight: 1
        $x_1_3 = "Application Data\\camelhair.udg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RD_2147833966_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RD!MTB"
        threat_id = "2147833966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gardenmaking.lnk" ascii //weight: 1
        $x_1_2 = "Software\\Ungdomssektioner" ascii //weight: 1
        $x_1_3 = "Takistoskops230.lnk" ascii //weight: 1
        $x_1_4 = "Chelations.ini" ascii //weight: 1
        $x_1_5 = "Uninstall\\Overhangs" ascii //weight: 1
        $x_1_6 = "Appetitlsestes.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RD_2147833966_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RD!MTB"
        threat_id = "2147833966"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Pladrende" wide //weight: 1
        $x_1_2 = "Preassigns.ini" wide //weight: 1
        $x_1_3 = "Antimensium.dll" wide //weight: 1
        $x_1_4 = "Anencephalia.ini" wide //weight: 1
        $x_1_5 = "Uninstall\\Blodrigt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FW_2147834096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FW!MTB"
        threat_id = "2147834096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "proinvestment Arbejdssgningers svineskinds" wide //weight: 1
        $x_1_2 = "nettosalgsprisens Stilhederne Delproblemerne" wide //weight: 1
        $x_1_3 = "Stofskiftesygdoms" wide //weight: 1
        $x_1_4 = "Lilleskolen" wide //weight: 1
        $x_1_5 = "Sedile" wide //weight: 1
        $x_1_6 = "unknowndll.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RG_2147834512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RG!MTB"
        threat_id = "2147834512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 53 57 ff 55 f8 [0-32] 8b c1 [0-1] 6a 0c [0-1] 5e f7 fe 8a 82 ?? ?? ?? ?? 30 04 39 41 3b cb 72 ea}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RG_2147834512_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RG!MTB"
        threat_id = "2147834512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 56 6a 00 ff d7 53 6a 01 8b f8 56 57 e8 [0-32] 03 d2 03 d2 8b c1 2b c2 8a ?? ?? ?? ?? ?? 30 14 39 41 3b ce 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RG_2147834512_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RG!MTB"
        threat_id = "2147834512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CurrentVersion\\Uninstall\\affectible" wide //weight: 1
        $x_1_2 = "vaucheriaceae.dat" wide //weight: 1
        $x_1_3 = "Burgundere7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RG_2147834512_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RG!MTB"
        threat_id = "2147834512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "andoverfladen.ini" wide //weight: 1
        $x_1_2 = "Selskabslokalers.lnk" wide //weight: 1
        $x_1_3 = "Software\\Chaparraz" wide //weight: 1
        $x_1_4 = "Scaphocephalic.ini" wide //weight: 1
        $x_1_5 = "Reproachful.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPW_2147834599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPW!MTB"
        threat_id = "2147834599"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 85 ?? fd ff ff 50 ff 55 d8 89 45 ec 83 7d ec ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPX_2147834600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPX!MTB"
        threat_id = "2147834600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c3 31 ed 55 50 ff d6 89 c6 6a 40 68 00 30 00 00 50 55 ff 15 ?? ?? ?? ?? 89 c7 89 e0 55 50 56 57 53 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPX_2147834600_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPX!MTB"
        threat_id = "2147834600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vareindkbenes.Til" ascii //weight: 1
        $x_1_2 = "sideordnet.sli" ascii //weight: 1
        $x_1_3 = "palliates\\cooing" ascii //weight: 1
        $x_1_4 = "Betingelsesdelens" ascii //weight: 1
        $x_1_5 = "Autoklaveringer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPX_2147834600_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPX!MTB"
        threat_id = "2147834600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Parbate.Rea" ascii //weight: 1
        $x_1_2 = "Fiercening\\Virtus" ascii //weight: 1
        $x_1_3 = "Angrebsmetoder165.Lkk" ascii //weight: 1
        $x_1_4 = "Uninstall\\Litiopa" ascii //weight: 1
        $x_1_5 = "Software\\Rooyebok" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPX_2147834600_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPX!MTB"
        threat_id = "2147834600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Tilblivelseshistoriers126\\Streaker" wide //weight: 1
        $x_1_2 = "Fonobsninger" wide //weight: 1
        $x_1_3 = "Sklmen91\\Udkommenter\\Luxurious" wide //weight: 1
        $x_1_4 = "Kleptomanernes\\Aarende164" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPX_2147834600_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPX!MTB"
        threat_id = "2147834600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Primnesses\\Sofabordets\\Adreamed" wide //weight: 1
        $x_1_2 = "Scorer.ini" wide //weight: 1
        $x_1_3 = "Uninstall\\frases\\Dribbet\\Darktown" wide //weight: 1
        $x_1_4 = "Afskydningerne44" wide //weight: 1
        $x_1_5 = "Nonreprehensibly.Ber" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPY_2147834601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPY!MTB"
        threat_id = "2147834601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d 95 ?? fd ff ff ?? ff 55 d8 89 45 ec 83 7d ec ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPY_2147834601_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPY!MTB"
        threat_id = "2147834601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sphacelus\\Snniker" ascii //weight: 1
        $x_1_2 = "krypteringspolitik" ascii //weight: 1
        $x_1_3 = "tippeladet" ascii //weight: 1
        $x_1_4 = "Sprydstagernes.ini" ascii //weight: 1
        $x_1_5 = "pnheds.Eur" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPY_2147834601_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPY!MTB"
        threat_id = "2147834601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Undervisningssystemer" wide //weight: 1
        $x_1_2 = "Software\\Renewals128\\temnospondylous\\Ldreplejens" wide //weight: 1
        $x_1_3 = "Summationens.Stv" wide //weight: 1
        $x_1_4 = "Dekuperes.Myr" wide //weight: 1
        $x_1_5 = "reimert.Wil" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RH_2147834897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RH!MTB"
        threat_id = "2147834897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 68 00 09 3d 00 6a 00 ff 15 ?? ?? ?? ?? 89 45 f4 83 7d f4 00 75 07 [0-32] 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8b 4d 10 51 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RH_2147834897_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RH!MTB"
        threat_id = "2147834897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 56 57 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 89 45 b0 8b 45 10 68 00 00 00 80 50 ff 15 ?? ?? ?? ?? 8b f0 6a 00 56 ff 15 ?? ?? ?? ?? 6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RH_2147834897_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RH!MTB"
        threat_id = "2147834897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Inkorporeredes.lnk" ascii //weight: 1
        $x_1_2 = "Felines.dll" ascii //weight: 1
        $x_1_3 = "Uninstall\\Prehensive\\Indesprringernes" ascii //weight: 1
        $x_1_4 = "Vagerbje.ini" ascii //weight: 1
        $x_1_5 = "Funktionrlovenen.Blo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RH_2147834897_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RH!MTB"
        threat_id = "2147834897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Udsgninger.ini" wide //weight: 1
        $x_1_2 = "Gerningsstederne.ini" wide //weight: 1
        $x_1_3 = "Spurl.ini" wide //weight: 1
        $x_1_4 = "Actinidiaceae.dll" wide //weight: 1
        $x_1_5 = "whitetip.lnk" wide //weight: 1
        $x_1_6 = "Stresslessness.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RH_2147834897_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RH!MTB"
        threat_id = "2147834897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Epithet.ini" wide //weight: 1
        $x_1_2 = "Moralizingly.dll" wide //weight: 1
        $x_1_3 = "Software\\Denarcotize" wide //weight: 1
        $x_1_4 = "Venskabsaftales.ini" wide //weight: 1
        $x_1_5 = "Uninstall\\Fishwoman" wide //weight: 1
        $x_1_6 = "Konfidensintervallets.Mia" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RI_2147834898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RI!MTB"
        threat_id = "2147834898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2b 5c 24 04 89 d8 c1 e8 1f 01 d8 2b 3c 24 d1 f8 89 f9 c1 e9 1f 01 f9 d1 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RI_2147834898_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RI!MTB"
        threat_id = "2147834898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 6a 40 68 00 30 00 00 68 00 09 3d 00 33 c9 89 45 f0 33 ff 89 45 f4 57 89 4d fc 89 45 ec ff d3 [0-37] 56 51 68 80 00 00 00 6a 03 51 6a 01 68 00 00 00 80 ff 75 10 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RI_2147834898_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RI!MTB"
        threat_id = "2147834898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 5a 62 02 e8 ?? ?? ?? ?? 83 c4 04 89 45 f0 68 00 5a 62 02 68 ff 00 00 00 8b 45 f0 50 e8 ?? ?? ?? ?? 83 c4 0c 83 7d f0 00 75 07 33 c0 e9 ?? ?? ?? ?? 8d 8d c0 fd ff ff 51 68 03 01 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RI_2147834898_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RI!MTB"
        threat_id = "2147834898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 09 3d 00 6a 08 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 89 45 ?? 83 7d ?? 00 75 05 e9 ?? ?? ?? ?? 68 00 09 3d 00 [0-112] 89 45 ?? 6a 40 68 00 30 00 00 8b [0-3] 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RI_2147834898_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RI!MTB"
        threat_id = "2147834898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Aftersupper.ini" ascii //weight: 1
        $x_1_2 = "Midtsamling.For" ascii //weight: 1
        $x_1_3 = "Suspendyjr.ini" ascii //weight: 1
        $x_1_4 = "Software\\Irrevocably" ascii //weight: 1
        $x_1_5 = "uncivilness.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RI_2147834898_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RI!MTB"
        threat_id = "2147834898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Linjevogters188.ini" wide //weight: 1
        $x_1_2 = "Eftersporet.Bra" wide //weight: 1
        $x_1_3 = "metastoma.ini" wide //weight: 1
        $x_1_4 = "Amphistomum.dll" wide //weight: 1
        $x_1_5 = "Kreatic.ini" wide //weight: 1
        $x_1_6 = "Uenighed.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RJ_2147834899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RJ!MTB"
        threat_id = "2147834899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 68 00 5a 62 02 6a 00 ff 55}  //weight: 1, accuracy: High
        $x_1_2 = {81 e1 03 09 01 00 81 e2 61 12 00 00 35 d3 6f 00 00 81 c2 c9 55 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RJ_2147834899_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RJ!MTB"
        threat_id = "2147834899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d8 59 59 85 db 74 21 8b f3 2b f7 d1 fe 03 f6 56 57 8b 7d f4 57}  //weight: 1, accuracy: High
        $x_1_2 = {0f b7 16 66 85 d2 74 11 83 fa 22 74 05 66 89 14 47 40 83 c6 02 3b c1 7c e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RJ_2147834899_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RJ!MTB"
        threat_id = "2147834899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 09 3d 00 6a 54 8b 45 e4 50 e8 [0-16] 6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 b9 04 00 00 00 c1 e1 00 8b 55 0c 8b 04 0a 50 [0-32] 6a 40 68 00 30 00 00 8b 55 94 52 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RJ_2147834899_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RJ!MTB"
        threat_id = "2147834899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Fortyndede\\Nonactives" ascii //weight: 1
        $x_1_2 = "Software\\Uprofessionel\\Teskefuld" ascii //weight: 1
        $x_1_3 = "Posits.lnk" ascii //weight: 1
        $x_1_4 = "Tsattine\\Vies.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RJ_2147834899_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RJ!MTB"
        threat_id = "2147834899"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Indsnuses.ini" wide //weight: 1
        $x_1_2 = "Slaafejlens.Hle" wide //weight: 1
        $x_1_3 = "Regningsarts.ini" wide //weight: 1
        $x_1_4 = "Housecoatene114.ini" wide //weight: 1
        $x_1_5 = "Elementbyggeriernes.ini" wide //weight: 1
        $x_1_6 = "Knappenaalshoveder.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FX_2147835210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FX!MTB"
        threat_id = "2147835210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 45 ec 6a 40 68 00 30 00 00 8b ?? ec ?? 6a 00 ff 15}  //weight: 10, accuracy: Low
        $x_10_2 = {89 45 f0 6a 40 68 00 30 00 00 8b ?? f0 ?? 6a 00 ff 15}  //weight: 10, accuracy: Low
        $x_10_3 = {6a 40 68 00 30 00 00 8b d8 53 57 ff 15}  //weight: 10, accuracy: High
        $x_5_4 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8d ?? d4 fe ff ff ?? ff 15}  //weight: 5, accuracy: Low
        $x_5_5 = {57 68 80 00 00 00 6a 03 57 6a 01 68 00 00 00 80 50 ff 15}  //weight: 5, accuracy: High
        $x_1_6 = {88 4d ff 8b 55 f4 03 55 f8 8a 45 ff 88 02 e9 ?? ?? ?? ?? 6a 00 8b 4d f4 51 ff 15 [0-6] 8b e5 5d}  //weight: 1, accuracy: Low
        $x_1_7 = {88 45 ff 8b 4d f4 03 4d f8 8a 55 ff 88 11 e9 ?? ?? ?? ?? 6a 00 8b 45 f4 50 ff 15 [0-6] 33 c0 8b e5 5d c3}  //weight: 1, accuracy: Low
        $x_1_8 = {6a 00 57 ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b c9 c3 04 00 3b d3 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_NSISInject_SPS_2147836055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SPS!MTB"
        threat_id = "2147836055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 3b 04 6e 34 ed 04 1e 88 04 3b 47 3b 7d f0 72 ee}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RM_2147836215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RM!MTB"
        threat_id = "2147836215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 09 3d 00 6a 54 50 e8 ?? ?? ?? ?? 8b 45 0c 83 c4 0c 57 68 80 00 00 00 6a 03 57 6a 01 68 00 00 00 80 ff 70 04 ff 15 ?? ?? ?? ?? 8b f0 57 56 ff 15 ?? ?? ?? ?? 6a 40 68 00 30 00 00 50 57 89 45 fc ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RK_2147836336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RK!MTB"
        threat_id = "2147836336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 e4 03 55 f8 0f b6 02 33 c1 8b 4d e4 03 4d f8 88 01 8b 55 f8 83 c2 01 89 55 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RK_2147836336_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RK!MTB"
        threat_id = "2147836336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c0 01 6b c0 14 01 c1 8b 45 10 2b 45 f4 83 e8 01 6b c0 14 89 14 24}  //weight: 1, accuracy: High
        $x_1_2 = {c7 04 24 00 00 00 00 c7 44 24 04 00 09 3d 00 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RK_2147836336_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RK!MTB"
        threat_id = "2147836336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "opgravedes.dll" ascii //weight: 1
        $x_1_2 = "Anlgsopgaver.ini" ascii //weight: 1
        $x_1_3 = "Sydlig.ini" ascii //weight: 1
        $x_1_4 = "Cavaliered\\Portulakker.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RK_2147836336_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RK!MTB"
        threat_id = "2147836336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Uninstall\\Rhombovate\\Cachuchas" ascii //weight: 1
        $x_1_2 = "Raffias\\Actionfilmhelte\\Elimar\\Turnkmteatre.ini" ascii //weight: 1
        $x_1_3 = "Software\\Magasin\\Ostindien" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SRPA_2147836550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SRPA!MTB"
        threat_id = "2147836550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0f be 11 81 f2 a6 00 00 00 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11 83 c2 7a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AJ_2147837465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AJ!MTB"
        threat_id = "2147837465"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 68 80 00 00 00 6a 03 53 6a 01 68 00 00 00 80 8d 85 [0-4] 50 ff 15 [0-4] 8b f0 53 56 ff 15 [0-4] 6a 40 68 00 30 00 00 8b d8 53 6a 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AK_2147837479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AK!MTB"
        threat_id = "2147837479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 80 00 00 00 6a 03 6a 00 6a 01 89 45 b0 8b 45 10 68 00 00 00 80 50 ff 15 [0-4] 8b f0 6a 00 56 ff 15 [0-4] 6a 40 8b d8 68 00 30 00 00 53 6a 00 89 5d ac ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AL_2147837630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AL!MTB"
        threat_id = "2147837630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 00 68 80 00 00 00 6a 03 6a 00 6a 01 68 00 00 00 80 8b 4d 0c 8b 51 04 52 ff 15 [0-4] 89 45 ec 6a 00 8b 45 ec 50 ff 15 [0-4] 89 45 f8 6a 40 68 00 30 00 00 8b 4d f8 51 6a 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AM_2147837635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AM!MTB"
        threat_id = "2147837635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 37 34 3e 04 6d 34 be fe c0 34 a9 04 37 88 04 37 46 3b f3 72}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_NZA_2147837643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.NZA!MTB"
        threat_id = "2147837643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11 81 [0-5] 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 01 68 00 00 00 80 b9 04 00 00 00 c1 e1 00 8b 55 0c 8b 04 0a 50 ff 15 [0-4] 89 45 ec 6a 00 8b 4d ec 51 ff 15 [0-4] 89 45 f0 6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AN_2147837845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AN!MTB"
        threat_id = "2147837845"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 55 ff 81 f2 fb 00 00 00 88 55 ff 0f b6 45 ff 03 45 f4 88 45 ff 0f b6 4d ff 33 4d f4 88 4d ff 0f b6 55 ff f7 d2 88 55 ff 8b 45 e8 03 45 f4 8a 4d ff 88 08 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AO_2147838034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AO!MTB"
        threat_id = "2147838034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 e0 03 55 f8 0f b6 02 33 c1 8b 4d e0 03 4d f8 88 01 eb}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 0c 6a 40 68 00 30 00 00 8b 45 e4 50 6a 00 ff 15 [0-4] 89 45 e0 8b 4d f0 51 6a 01 8b 55 e4 52 8b 45 e0 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AP_2147838037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AP!MTB"
        threat_id = "2147838037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f4 99 b9 0c 00 00 00 f7 f9 8b 85 54 ff ff ff 0f b6 0c 10 8b 55 dc 03 55 f4 0f b6 02 33 c1 8b 4d dc 03 4d f4 88 01 eb}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 0c 6a 40 68 00 30 00 00 8b 55 d0 52 6a 00 ff 15 [0-4] 89 45 dc 8b 45 d4 50 6a 01 8b 4d d0 51 8b 55 dc 52 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_MBF_2147838092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.MBF!MTB"
        threat_id = "2147838092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 06 80 c1 7d 80 f1 86 80 c1 58 80 f1 e7 80 c1 77 80 f1 31 80 c1 03 80 f1 d0 fe c1 80 f1 3e 80 c1 43 80 f1 10 fe c1 88 0c 06 40 3b 45 f0 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_MBG_2147838093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.MBG!MTB"
        threat_id = "2147838093"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 11 81 f2 ?? ?? ?? ?? 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 0f be 11 83 ea 0e 8b 45 f8 03 45 fc 88 10 8b 4d f8 03 4d fc 8a 11 80 c2 01 8b 45 f8 03 45 fc 88 10 8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 3b 55}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 f0 6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AQ_2147838309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AQ!MTB"
        threat_id = "2147838309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 e0 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 f0 6a 00 6a 00 8b 4d f4 51 e8 [0-4] 83 c4 0c 6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AR_2147838405_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AR!MTB"
        threat_id = "2147838405"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c8 f7 e3 d1 ea 83 e2 fc 8d 04 52 f7 d8 8b 14 24 8a 04 07 30 04 0a 41 47 39 ce 75}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 04 89 c6 53 53 57 e8 [0-4] 83 c4 0c 6a 40 68 00 30 00 00 56 53 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AS_2147838495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AS!MTB"
        threat_id = "2147838495"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 4d ff 81 f1 b9 00 00 00 88 4d ff 0f b6 55 ff 2b 55 f8 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 8b 4d e8 03 4d f8 8a 55 ff 88 11 e9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AT_2147838620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AT!MTB"
        threat_id = "2147838620"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 f9 8b 45 e4 0f b6 0c 10 8b 55 dc 03 55 f4 0f b6 02 33 c1 8b 4d dc 03 4d f4 88 01 eb}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 04 89 45 e0 6a 00 6a 00 8b 4d e8 51 e8 [0-4] 83 c4 0c 6a 40 68 00 30 00 00 8b 55 e0 52 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_MBAQ_2147838767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.MBAQ!MTB"
        threat_id = "2147838767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c0 01 89 45 fc 8b 4d fc 3b 4d f0 73 27 8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 e4 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb c8}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 0c 6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AU_2147838768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AU!MTB"
        threat_id = "2147838768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 c8 89 45 c4 8b 45 dc b9 0c 00 00 00 99 f7 f9 8b 45 c4 0f b6 34 10 8b 45 e0 8b 4d dc 0f b6 14 08 31 f2 88 14 08 8b 45 dc 83 c0 01 89 45 dc e9}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 d8 31 c9 c7 04 24 00 00 00 00 89 44 24 04 c7 44 24 08 00 30 00 00 c7 44 24 0c 40 00 00 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AV_2147838788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AV!MTB"
        threat_id = "2147838788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 eb}  //weight: 2, accuracy: High
        $x_2_2 = {83 c4 04 89 45 f0 6a 00 6a 00 8b 4d f4 51 e8 [0-4] 83 c4 0c 6a 40 68 00 30 00 00 8b 55 f0 52 6a 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SPQP_2147838943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SPQP!MTB"
        threat_id = "2147838943"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 37 fe c8 34 17 04 21 34 98 04 55 34 fc 04 15 88 04 37 46 3b f3 72 e7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_MBAR_2147839240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.MBAR!MTB"
        threat_id = "2147839240"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b c1 99 6a 0c 5e f7 fe 8a 82 3c b2 40 00 30 04 19 41 3b cf 72 ea}  //weight: 1, accuracy: High
        $x_1_2 = {83 c4 24 6a 40 68 00 30 00 00 57 53 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_MBAG_2147839337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.MBAG!MTB"
        threat_id = "2147839337"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e6 c1 ea 03 8b c6 8d 0c 52 c1 e1 02 2b c1 46 8a 80 ?? ?? ?? ?? 30 44 1e ff 3b f7 72 dd}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 24 6a 40 68 00 30 00 00 57 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_MBAI_2147839442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.MBAI!MTB"
        threat_id = "2147839442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f7 e6 8b c6 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 8a 80 ?? ?? ?? ?? 30 04 1e 46 3b f7 72 de}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 24 6a 40 68 00 30 00 00 57 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SPAB_2147839705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SPAB!MTB"
        threat_id = "2147839705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {88 45 ff 0f b6 55 ff 2b 55 f4 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 4d ff 83 e9 37 88 4d ff 0f b6 55 ff 33 55 f4 88 55 ff 0f b6 45 ff 83 c0 17 88 45 ff 8b 4d e8 03 4d f4 8a 55 ff 88 11 e9 29 ff ff ff}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_MBAL_2147840160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.MBAL!MTB"
        threat_id = "2147840160"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 10 03 c1 89 45 f4 8b c1 99 6a 0c 5f f7 ff 8b 7d f4 8a 82 ?? ?? ?? ?? 30 07 41 3b cb 72 e0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 24 6a 40 68 00 30 00 00 53 56 ff 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AW_2147840547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AW!MTB"
        threat_id = "2147840547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Paristhmic\\Speedometerets119.Fac" ascii //weight: 1
        $x_1_2 = "Sheltas\\Afregningspriser.ini" ascii //weight: 1
        $x_1_3 = "Frankable\\Ankergangs\\Unhoroscopic\\Crayonist.Pro" ascii //weight: 1
        $x_1_4 = "Stilleknaps133\\Undervisningspligternes\\Forstanderindernes\\Carpi" ascii //weight: 1
        $x_1_5 = "Software\\varefordelinger\\Womanhood" ascii //weight: 1
        $x_1_6 = "Landeveje%\\Circe.You" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AX_2147840822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AX!MTB"
        threat_id = "2147840822"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 8b 75 10 6a 01 8b d8 56 53 e8 [0-4] 83 c4 10 85 f6 74}  //weight: 2, accuracy: Low
        $x_2_2 = {8b c7 99 6a 0c 59 f7 f9 8a 82 [0-4] 30 04 1f 47 3b fe 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AY_2147840924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AY!MTB"
        threat_id = "2147840924"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c1 99 6a 0c 5e f7 fe 8a 82 [0-4] 30 04 0b 41 3b cf 72}  //weight: 2, accuracy: Low
        $x_2_2 = {83 c4 24 6a 40 68 00 30 00 00 57 53 ff 15 [0-4] 56 6a 01 8b d8 57 53 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_AZ_2147841156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.AZ!MTB"
        threat_id = "2147841156"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tomers\\Helgardere\\Rebukers\\Warreners.Sku" ascii //weight: 1
        $x_1_2 = "Paatalers\\preengage\\Forbrugsforeningerne\\Oxybenzaldehyde.Vin" ascii //weight: 1
        $x_1_3 = "Software\\Hotelvrterne\\Colourfast\\Churchier" ascii //weight: 1
        $x_1_4 = "Cornbell.Who" ascii //weight: 1
        $x_1_5 = "Squirmers\\Biseksualiteten\\Occidentalises\\Filmapparater.Afn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BA_2147841321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BA!MTB"
        threat_id = "2147841321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 0c 6a 40 68 00 30 00 00 53 57 ff 15 [0-4] 56 6a 01 8b f8 53 57 e8 [0-4] 83 c4 10 33 c9 85 db 74 16 8b c1 6a 0c 99 5e f7 fe 8a 82 [0-4] 30 04 0f 41 3b cb 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BB_2147841327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BB!MTB"
        threat_id = "2147841327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 c4 0c 6a 40 68 00 30 00 00 53 57 ff 15 [0-4] 56 6a 01 8b f8 53 57 e8 [0-4] 83 c4 10 33 c9 85 db 74 16 8b c1 99 6a 0c 5e f7 fe 8a 82 [0-4] 30 04 0f 41 3b cb 72}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RL_2147843250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RL!MTB"
        threat_id = "2147843250"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {99 b9 0c 00 00 00 f7 f9 8b 45 ec 0f b6 0c 10 8b 55 f0 03 55 fc 0f b6 02 33 c1 8b 4d f0 03 4d fc 88 01 8b 55 fc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BC_2147844004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BC!MTB"
        threat_id = "2147844004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 f0 0f b6 0c 10 8b 55 f8 03 55 fc 0f b6 02 33 c1 8b 4d f8 03 4d fc 88 01 8b 55 fc 83 c2 01 89 55 fc eb}  //weight: 2, accuracy: High
        $x_2_2 = {83 c4 08 89 45 f4 6a 40 68 00 30 00 00 68 [0-4] 6a 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPZ_2147845449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPZ!MTB"
        threat_id = "2147845449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Halvtredsaarige\\sunnittens\\Rgtende" ascii //weight: 1
        $x_1_2 = "Slavens.sub" ascii //weight: 1
        $x_1_3 = "Kommissionere198" ascii //weight: 1
        $x_1_4 = "Marmorhvidt.Spr" ascii //weight: 1
        $x_1_5 = "Diphenoxylate.Nae" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPZ_2147845449_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPZ!MTB"
        threat_id = "2147845449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kloakeringsbeslutnings" wide //weight: 1
        $x_1_2 = "Indlodsedes196" wide //weight: 1
        $x_1_3 = "oppositional.She" wide //weight: 1
        $x_1_4 = "diversiform\\resublimating" wide //weight: 1
        $x_1_5 = "opbygningsfasers" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPZ_2147845449_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPZ!MTB"
        threat_id = "2147845449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Filmvidenskabs\\Limbmeal" wide //weight: 1
        $x_1_2 = "Software\\Upclimber183" wide //weight: 1
        $x_1_3 = "Irride.Man" wide //weight: 1
        $x_1_4 = "Mikroorganisme" wide //weight: 1
        $x_1_5 = "Indflder\\Afrodisiakas\\Purken.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RPZ_2147845449_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RPZ!MTB"
        threat_id = "2147845449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Industriferiens.Car" wide //weight: 1
        $x_1_2 = "Sanjakship\\Extravagances\\Muldvarpeskud" wide //weight: 1
        $x_1_3 = "Software\\Antimaniacal\\Bogladeprisens" wide //weight: 1
        $x_1_4 = "Fibrillated252" wide //weight: 1
        $x_1_5 = "Ampere.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BD_2147845675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BD!MTB"
        threat_id = "2147845675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Trochanteral\\Elegises\\Totalafholdende" ascii //weight: 1
        $x_1_2 = "Software\\Ejvins\\Videocast\\overeksponeredes" ascii //weight: 1
        $x_1_3 = "Beskydningernes.Vis" ascii //weight: 1
        $x_1_4 = "Inductophone.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BE_2147845744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BE!MTB"
        threat_id = "2147845744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\utilbjeligheder" ascii //weight: 1
        $x_1_2 = "Software\\Extratropical\\Fremmedsprogsundervisningen" ascii //weight: 1
        $x_1_3 = "Undergraduatedom\\personkreds.Dem" ascii //weight: 1
        $x_1_4 = "Software\\Coseasonal\\Aggrandizement\\Mesosternal\\Theorisers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BF_2147847082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BF!MTB"
        threat_id = "2147847082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Paravant\\Stoppage\\syllabogram\\Citrullin.ini" ascii //weight: 1
        $x_1_2 = "Hulster\\Agrarkonomer\\Dispreader.dll" ascii //weight: 1
        $x_1_3 = "Sunsets\\Hovedkorts\\Dybfrostens\\Plateresque.Sta" ascii //weight: 1
        $x_1_4 = "applikere\\Spellword.sem" ascii //weight: 1
        $x_1_5 = "Software\\Nonnatively\\Turdine" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BG_2147847091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BG!MTB"
        threat_id = "2147847091"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "softy\\Stadionet\\Slipperiest.Sel" ascii //weight: 1
        $x_1_2 = "Software\\Listeafstemningerne\\Greekling" ascii //weight: 1
        $x_1_3 = "Ecbolic\\Arty\\Gravsten233.lnk" ascii //weight: 1
        $x_1_4 = "Headlongwise\\landsplanlgningerne\\Egelvet\\Informationsstrms.Fjl" ascii //weight: 1
        $x_1_5 = "Software\\Ninetts\\Predictiveness\\Basnglens" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_FZ_2147847961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.FZ!MTB"
        threat_id = "2147847961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 0c 10 8b 55 ?? 03 55 ?? 0f b6 02 33 c1 8b 4d ?? 03 4d ?? 88 01 8b 55 ?? 83 c2 01 89 55 ?? 81 7d ?? ?? ?? ?? ?? 7d 0e 00 8b 45 ?? 99 b9 ?? ?? ?? ?? f7 f9 8b 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BH_2147848121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BH!MTB"
        threat_id = "2147848121"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Camittas\\Aromastoffers\\Mark\\fyraab.Pla" ascii //weight: 1
        $x_1_2 = "Navarre\\Receptors\\Refamiliarize\\spartacism\\Mergh.You" ascii //weight: 1
        $x_1_3 = "Binominous\\bortliciterer\\Flugtbilen.Reg" ascii //weight: 1
        $x_1_4 = "Bedsteborgerliges\\Ostraite.Lys" ascii //weight: 1
        $x_1_5 = "Software\\Auktioners\\Halvdels\\Nedlggende\\Belimousined" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BI_2147848449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BI!MTB"
        threat_id = "2147848449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Leveringstidspunkt\\Dbefonternes\\Sexennial230\\Macrophage.ini" ascii //weight: 1
        $x_1_2 = "Entrecotes\\Neutraliseringsanlggets\\Diswont.Sch" ascii //weight: 1
        $x_1_3 = "Bomstrkt\\Vognbjrn.ini" ascii //weight: 1
        $x_1_4 = "Skydkkes\\sekundavarerne\\dissented" ascii //weight: 1
        $x_1_5 = "Software\\spliff\\Paasaetning\\biotopes" ascii //weight: 1
        $x_1_6 = "Software\\Sanatoriet\\Stemningsblgers\\Inanimatenesses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BJ_2147848450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BJ!MTB"
        threat_id = "2147848450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sexbomberne\\Interfirm\\Exhibitionist.Uni" ascii //weight: 1
        $x_1_2 = "Hensygne\\Adjunkturer66\\Overcompensators\\Soubrettes.Hel" ascii //weight: 1
        $x_1_3 = "Software\\Escrows\\Jongleret\\Brevduer" ascii //weight: 1
        $x_1_4 = "Software\\vannus\\Agitates66\\Gastrostaxis\\grilladed" ascii //weight: 1
        $x_1_5 = "Titoisten\\Toiletry160\\Coffinmaker.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_GA_2147848585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.GA!MTB"
        threat_id = "2147848585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_FileExists@4" ascii //weight: 1
        $x_1_2 = "HvDeclY" ascii //weight: 1
        $x_1_3 = "_ReadFileContents@12" ascii //weight: 1
        $x_1_4 = "_WriteToFile@12" ascii //weight: 1
        $x_1_5 = "Loader.dll" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "IsProcessorFeaturePresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BK_2147848917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BK!MTB"
        threat_id = "2147848917"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 0c 31 30 46 01 8d 76 03 b8 [0-4] f7 e1 8b c3 83 c3 03 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 0f b6 80 [0-4] 30 46 ff 81 fb d3 17 00 00 7c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BL_2147848918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BL!MTB"
        threat_id = "2147848918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 45 fc 99 b9 0c 00 00 00 f7 f9 8b 45 e8 0f b6 0c 10 8b 55 d4 03 55 fc 0f b6 02 33 c1 8b 4d d4 03 4d fc 88 01 eb}  //weight: 2, accuracy: High
        $x_2_2 = {89 45 f8 6a 40 68 00 10 00 00 68 6e 16 00 00 6a 00 ff 55}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BM_2147848939_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BM!MTB"
        threat_id = "2147848939"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lbetrning\\Cigarrullerens153\\Accomplement\\Myndighedens.ini" ascii //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Vekselstrmmens\\Berkeleian" ascii //weight: 1
        $x_1_3 = "CurrentVersion\\Uninstall\\Bedeafen\\Tjenstledigt\\Spildevandsudledning" ascii //weight: 1
        $x_1_4 = "Ascape\\Rensningsformerne.ini" ascii //weight: 1
        $x_1_5 = "Minoriteternes\\Humus\\Chaetophora\\jorams" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BN_2147849064_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BN!MTB"
        threat_id = "2147849064"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 42 01 99 f7 ff 0f b6 41 fe c0 c8 03 32 82 [0-4] 88 41 fe 8d 42 01 99 f7 ff 4e 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BO_2147849078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BO!MTB"
        threat_id = "2147849078"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 42 01 99 f7 ff 0f b6 41 fe c0 c8 03 32 82 [0-4] 88 41 fe 8d 42 01 99 f7 ff 83 ee 01 75}  //weight: 4, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 68 2b 16 00 00 8b f0 6a 00 89 75 fc ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BP_2147849176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BP!MTB"
        threat_id = "2147849176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 04 0e c0 c8 03 32 82 [0-4] 88 04 0e 8d 42 01 99 c7 45 fc 0c 00 00 00 f7 7d fc 41 81 f9 d9 15 00 00 7c}  //weight: 4, accuracy: Low
        $x_1_2 = {6a 40 68 00 10 00 00 68 d9 15 00 00 56 89 45 f8 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BQ_2147850607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BQ!MTB"
        threat_id = "2147850607"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8a 04 0f c0 c8 03 32 82 [0-4] 88 04 0f 8d 42 01 6a 0c 99 5e f7 fe 41 3b cb 72}  //weight: 4, accuracy: Low
        $x_1_2 = {55 8b ec 6a 40 68 00 30 00 00 ff 75 08 6a 00 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BR_2147850625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BR!MTB"
        threat_id = "2147850625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Fruity\\bjergvrksdriften" ascii //weight: 1
        $x_1_2 = "Interlocating\\Supereligibleness.Var" ascii //weight: 1
        $x_1_3 = "Software\\Gnaske\\Trisylabic\\Oculocephalic\\Preexaction" ascii //weight: 1
        $x_1_4 = "Bamboozled\\Koppevaccination\\Ldreliv.Gra" ascii //weight: 1
        $x_1_5 = "Uransagelighedens\\Brneteater.dll" ascii //weight: 1
        $x_1_6 = "Afspndingsmidlernes\\Stormasters206\\Senilises\\Journaliserende.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BS_2147850626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BS!MTB"
        threat_id = "2147850626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Missioneredes\\logistikfunktioner\\Talerafhnging.Acc" wide //weight: 1
        $x_1_2 = "Forsvensk\\limfabrikkers\\Retina\\Pullimuts.Bol" wide //weight: 1
        $x_1_3 = "Cysticercus\\Muta210\\Romanbladenes\\Epiplexis.lnk" wide //weight: 1
        $x_1_4 = "Chalana238\\Predisregard\\omdbningerne\\Skbnegudinde.Eft" wide //weight: 1
        $x_1_5 = "Tissemandens\\Pacifistisk\\Skaanes\\Heksejagtens.spr" wide //weight: 1
        $x_1_6 = "Lertjet\\Luftighedernes\\Prosaisterne.ini" wide //weight: 1
        $x_1_7 = "Skabilkenhovederne\\Gutium\\Traversere\\Overrisles.Prf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BT_2147850632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BT!MTB"
        threat_id = "2147850632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Exoticity67\\tyranniseringens.dll" ascii //weight: 1
        $x_1_2 = "Software\\rillerne\\exaggerativeness\\bemrkelsens" ascii //weight: 1
        $x_1_3 = "forbiers\\saftningerne\\unfailably.ini" ascii //weight: 1
        $x_1_4 = "showdown\\culgee\\Kompliment251\\skubberens.dll" ascii //weight: 1
        $x_1_5 = "Refunderer.unc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_A_2147850682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.A!MTB"
        threat_id = "2147850682"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Blanc-Sablon" ascii //weight: 2
        $x_2_2 = "HeitikiBurlHandlebarKohlrabi" ascii //weight: 2
        $x_2_3 = "gayals" ascii //weight: 2
        $x_2_4 = "ShogunSubmolecule" ascii //weight: 2
        $x_2_5 = "Benjy::Shawm" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_GB_2147851928_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.GB!MTB"
        threat_id = "2147851928"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 07 c0 c8 03 32 82 ?? ?? ?? ?? 6a 0c 88 07 8d 42 01 99 5f f7 ff 46 3b f1 72 07 00 8d bc 35}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SPXC_2147852775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SPXC!MTB"
        threat_id = "2147852775"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "janner.slv" ascii //weight: 1
        $x_1_2 = "klonede.tit" ascii //weight: 1
        $x_1_3 = "ciliolum.dll" ascii //weight: 1
        $x_1_4 = "laitances\\legat.ini" ascii //weight: 1
        $x_1_5 = "scoliidae\\Rosenrd.lnk" ascii //weight: 1
        $x_1_6 = "combiners\\galanterier\\ledelsesplaner\\sord.Dra33" ascii //weight: 1
        $x_1_7 = "numina\\chloroplatinous\\Rebenes\\fremfrelse.eve" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_BU_2147889039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.BU!MTB"
        threat_id = "2147889039"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bestyrelser\\Untaughtness\\Antirenter.ini" ascii //weight: 1
        $x_1_2 = "Tilstningsfri\\Preconcessions\\Pursuit\\Causticises.ini" ascii //weight: 1
        $x_1_3 = "Software\\Centraler\\Afdramatiseringens41\\Trykstbning" ascii //weight: 1
        $x_1_4 = "Software\\Restaureringens" ascii //weight: 1
        $x_1_5 = "Dubleringernes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SPGJ_2147889505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SPGJ!MTB"
        threat_id = "2147889505"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "plebeianising\\orographically.Sap" ascii //weight: 1
        $x_1_2 = "stersstrande\\apoplektiker\\humorlessnesses" ascii //weight: 1
        $x_1_3 = "nabobeboelsens\\Huldah\\tsade.ini" ascii //weight: 1
        $x_1_4 = "sammenstillingernes\\krre.sko" ascii //weight: 1
        $x_1_5 = "flagsptternes\\storborger\\unstavable\\steadiest.ini" ascii //weight: 1
        $x_1_6 = "Telefonstorme\\statistikprogrammers\\fuldblodshestes.for" ascii //weight: 1
        $x_1_7 = "Thorni38\\Haulages.udt" ascii //weight: 1
        $x_1_8 = "Recumbency217.koa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_NSISInject_PRF_2147891778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.PRF!MTB"
        threat_id = "2147891778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 d4 8a 04 05 00 60 ?? 00 88 45 d3 8b 45 c8 8b 4d cc 8a 04 08 88 45 d2 0f b6 45 d3 c1 f8 03 0f b6 4d d3 c1 e1 05 09 c8 0f b6 4d d2 31 c8 88 c1 8b 45 d4 88 0c 05 00 60 ?? 00 8b 45 cc 83 c0 01 b9 0d 00 00 00 99 f7 f9 89 55 cc 8b 45 d4 83 c0 01 89 45 d4 81 7d d4 ?? ?? 00 00 0f 83 05 00 00 00 e9 99 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_PRG_2147891866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.PRG!MTB"
        threat_id = "2147891866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d f8 8a ?? ?? ?? ?? ?? 88 55 ff 8b 45 e0 03 45 f4 8a 08 88 4d fe 0f b6 55 ff c1 fa 03 0f b6 45 ff c1 e0 05 0b d0 0f b6 4d fe 33 d1 8b 45 f8 88 ?? ?? ?? ?? ?? 8b 45 f4 83 c0 01 99 b9 0d ?? ?? ?? f7 f9 89 55 f4 8b 55 f8 83 c2 01 89 55 f8 81 7d f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_PRI_2147892282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.PRI!MTB"
        threat_id = "2147892282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 01 99 b9 0d 00 00 00 f7 f9 89 55 ?? 8b ?? ?? 83 ?? 01 89 ?? ?? 81 7d ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 01 b9 0d 00 00 00 99 f7 f9 89 55 ?? 8b ?? ?? 83 ?? 01 89 ?? ?? 81 7d ?? ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_NSISInject_GC_2147892416_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.GC!MTB"
        threat_id = "2147892416"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 04 68 00 30 00 00 68 00 65 cd 1d 8b f8 56 ff d7}  //weight: 1, accuracy: High
        $x_1_2 = {c0 c8 03 32 86 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 8d 46 01 99 41 f7 fb 8b f2 81 f9 ?? ?? ?? ?? 72 06 00 8a 81}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SMTY_2147896155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SMTY!MTB"
        threat_id = "2147896155"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e1 05 0b c1 0f b6 55 [0-3] 33 c2 8b 4d ?? 88 81 [0-5] 8b 45 [0-3] 83 c0 01 99 b9 0d 00 00 00 f7 f9 89 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SMTK_2147896604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SMTK!MTB"
        threat_id = "2147896604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 05 00 00 43 00 88 45 f7 8b 45 ec 8b 4d f0 8a 04 08 88 45 f6 0f b6 45 f7 c1 f8 03 0f b6 4d f7 c1 e1 05 09 c8 0f b6 4d f6 31 c8 88 c1 8b 45 f8 88 0c 05 00 00 43 00 8b 45 f0 83 c0 01 b9 0d 00 00 00 99 f7 f9 89 55 f0 8b 45 f8 83 c0 01 89 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SMTK_2147896604_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SMTK!MTB"
        threat_id = "2147896604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 85 23 e2 ff ff c1 f8 03 0f b6 8d 23 e2 ff ff c1 e1 05 09 c8 0f b6 8d 22 e2 ff ff 31 c8 88 c1 8b 85 24 e2 ff ff 88 8c 05 2b e2 ff ff 8b 85 1c e2 ff ff 83 c0 01 b9 0d 00 00 00 99 f7 f9 89 95 1c e2 ff ff 8b 85 24 e2 ff ff 83 c0 01 89 85 24 e2 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_CF_2147898327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.CF!MTB"
        threat_id = "2147898327"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Omadressering.sla" ascii //weight: 1
        $x_1_2 = "Sluknende.txt" ascii //weight: 1
        $x_1_3 = "bluffmagerne.fed" ascii //weight: 1
        $x_1_4 = "Software\\tormentillerne" ascii //weight: 1
        $x_1_5 = "unmuted.mal" ascii //weight: 1
        $x_1_6 = "mavekatar.con" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SPXX_2147898438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SPXX!MTB"
        threat_id = "2147898438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hemophiliacs.txt" ascii //weight: 1
        $x_1_2 = "morallren.ini" ascii //weight: 1
        $x_1_3 = "Tovbane.ind" ascii //weight: 1
        $x_1_4 = "hyetometer.Rub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RX_2147903572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RX!MTB"
        threat_id = "2147903572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tandlgeklinikker212.mar" ascii //weight: 1
        $x_1_2 = "C:\\TEMP\\overmandede\\Metran" ascii //weight: 1
        $x_1_3 = "SYSTEM32\\energetiskes\\Physicianer223.lnk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_RX_2147903572_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.RX!MTB"
        threat_id = "2147903572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Snifnings59\\Glansrollen.Ine" wide //weight: 1
        $x_1_2 = "flaadninger.ini" wide //weight: 1
        $x_1_3 = "Squirarchy.Aff" wide //weight: 1
        $x_1_4 = "Etatsraads.Sla" wide //weight: 1
        $x_1_5 = "toilettes.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_VNC_2147923977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.VNC!MTB"
        threat_id = "2147923977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "silkaline svrestes.exe" ascii //weight: 1
        $x_1_2 = "brinkernes gendarmeris" ascii //weight: 1
        $x_1_3 = "presbyteriansk.rdb" ascii //weight: 1
        $x_1_4 = "Venstrehaandsarbejderne.agb" ascii //weight: 1
        $x_1_5 = "Skaft.Gen" ascii //weight: 1
        $x_1_6 = "caudotibial" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_VND_2147924030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.VND!MTB"
        threat_id = "2147924030"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "antivaccinator because.exe" ascii //weight: 1
        $x_1_2 = "fuldblodsopdrtteren screen" ascii //weight: 1
        $x_1_3 = "gratulant svrdfste gttet" ascii //weight: 1
        $x_1_4 = "Delicately\\oplgets.ini" ascii //weight: 1
        $x_1_5 = "skumringstimers\\Uninstall\\negress\\Forladernes" ascii //weight: 1
        $x_1_6 = "hurriers\\balletkorps" ascii //weight: 1
        $x_1_7 = "protomerite\\blokeringerne\\kirkeministeriets" ascii //weight: 1
        $x_1_8 = "Vanskeliggjordes88.bru" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_VNE_2147924031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.VNE!MTB"
        threat_id = "2147924031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inanity.exe" ascii //weight: 1
        $x_1_2 = "hahnemannian malaysisk" ascii //weight: 1
        $x_1_3 = "moratorium flankeringer studiekredsenes" ascii //weight: 1
        $x_1_4 = "udsavning" ascii //weight: 1
        $x_1_5 = "1d1h1l1p1t1x1|1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SLF_2147924993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SLF!MTB"
        threat_id = "2147924993"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "overskuedes.cha" ascii //weight: 1
        $x_1_2 = "twit.jen" ascii //weight: 1
        $x_1_3 = "denotationen.unr" ascii //weight: 1
        $x_1_4 = "\\rdbgens\\halifax.dll" ascii //weight: 1
        $x_1_5 = "\\fetaens\\scaphiopus.Aan31" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SHBD_2147932602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SHBD!MTB"
        threat_id = "2147932602"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "soldaterhjemmene" wide //weight: 2
        $x_1_2 = "svingningshastigheds\\Frakkekraver220.Lab203" wide //weight: 1
        $x_1_3 = "pericentric\\chocking\\Ropemanship0" wide //weight: 1
        $x_1_4 = "Undisturbedness106\\presanctify" wide //weight: 1
        $x_1_5 = "chaussee.su" wide //weight: 1
        $x_1_6 = "Strmforholdene.min" wide //weight: 1
        $x_1_7 = "refloated\\Arbejdstilbuddenes171.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SXBM_2147932694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SXBM!MTB"
        threat_id = "2147932694"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "epileptoid\\Charmetrolden" ascii //weight: 2
        $x_1_2 = "bintjekartoffelen.avo" ascii //weight: 1
        $x_1_3 = "Lukketiders227\\siouxens" ascii //weight: 1
        $x_1_4 = "Denotatum.ini" ascii //weight: 1
        $x_1_5 = "Glyptograph.txt" ascii //weight: 1
        $x_1_6 = "Subsistenslse.ini" ascii //weight: 1
        $x_1_7 = "Afdelingssygeplejerske.Hur197" ascii //weight: 1
        $x_1_8 = "procatalectic.mis" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SVM_2147933796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SVM!MTB"
        threat_id = "2147933796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Erythromania224\\sammenhobningernes" ascii //weight: 3
        $x_2_2 = "Regeringerne205\\prioritetsrkkeflgens" ascii //weight: 2
        $x_2_3 = "Arabesks\\Uninstall\\impeach\\barselsorloverne" ascii //weight: 2
        $x_1_4 = "Halvfemser\\luftspringenes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SVM_2147933796_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SVM!MTB"
        threat_id = "2147933796"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "beniamino\\Uninstall\\accorded\\junglier" ascii //weight: 2
        $x_2_2 = "Tilsynsfrendes.dho" ascii //weight: 2
        $x_2_3 = "coexert\\kredse.met" ascii //weight: 2
        $x_2_4 = "Triveligste111.fag" ascii //weight: 2
        $x_2_5 = "quodlibetarian.ini" ascii //weight: 2
        $x_2_6 = "flammekasterens.ini" ascii //weight: 2
        $x_1_7 = "dislustered.sub" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_NSISInject_SH_2147959244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NSISInject.SH!MTB"
        threat_id = "2147959244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NSISInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "starbowlines turnkey sygemeldings" ascii //weight: 1
        $x_1_2 = "halvkusiner" ascii //weight: 1
        $x_1_3 = "lysstyrken femalise" ascii //weight: 1
        $x_1_4 = "RegDeleteKeyW" ascii //weight: 1
        $x_1_5 = "RegOpenKeyExW" ascii //weight: 1
        $x_1_6 = "SetClipboardData" ascii //weight: 1
        $x_1_7 = "LoadBitmapW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

