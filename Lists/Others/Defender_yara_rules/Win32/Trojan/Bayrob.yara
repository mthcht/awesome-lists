rule Trojan_Win32_Bayrob_SIB_2147805771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.SIB!MTB"
        threat_id = "2147805771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c1 89 da ?? [0-96] 89 11 83 c1 04 [0-48] 83 ea ?? [0-10] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {31 db e9 e3 [0-48] 8b 8a ?? ?? ?? ?? [0-16] 33 1c 8f [0-160] 83 c2 04 [0-10] 39 d0 [0-10] 0f 84 ?? ?? ?? ?? [0-80] e9}  //weight: 1, accuracy: Low
        $x_1_3 = {89 74 24 04 89 3c 24 [0-48] e8 ?? ?? ?? ?? [0-48] 89 3c 24 [0-10] e8 ?? ?? ?? ?? [0-64] 33 1d 69 76 43 00 [0-170] b8 20 51 43 00 29 d8 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_ARA_2147902715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.ARA!MTB"
        threat_id = "2147902715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 10 30 11 41 40 3b cf 75 f6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_ARA_2147902715_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.ARA!MTB"
        threat_id = "2147902715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 39 00 74 ?? 80 31 1a 41 eb f5}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_ARAQ_2147908940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.ARAQ!MTB"
        threat_id = "2147908940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 04 37 30 06 ff 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MA_2147917204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MA!MTB"
        threat_id = "2147917204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 c0 75 04 32 c0 5d c3 e8 1e ef 02 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MB_2147917205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MB!MTB"
        threat_id = "2147917205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 33 f6 39 75 08 0f 95 c0 3b c6 75 20 e8 78 11 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MD_2147917206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MD!MTB"
        threat_id = "2147917206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5e 89 30 e8 73 f7 ff ff 80 7d fc 00 74 07 8b 45 f8 83 60 70 fd 8b c6 5e 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MME_2147918777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MME!MTB"
        threat_id = "2147918777"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 07 50 e8 ea fb ff ff 59 e8 ed 68 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MH_2147918778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MH!MTB"
        threat_id = "2147918778"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 11 c7 45 fc fe ff ff ff b8 ff 00 00 00 e9 04 01 00 00 68 14 62 49 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MK_2147918779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MK!MTB"
        threat_id = "2147918779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 c8 89 45 08 8b d0 8a 45 08 c1 ea 08 02 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MK_2147918779_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MK!MTB"
        threat_id = "2147918779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 11 29 d1 31 f6 8a 1c 32 88 1c 30 46 39 f1 75 f5 01 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_ML_2147922781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.ML!MTB"
        threat_id = "2147922781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 02 8b df 3b f3 75 d1 5f 5d 8b c6 5e 5b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MM_2147922782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MM!MTB"
        threat_id = "2147922782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f bf c8 89 4d fc 57 56 db 45}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MN_2147923417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MN!MTB"
        threat_id = "2147923417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b f0 33 ff 39 3e 74 1a 56 e8 c8 04 00 00 59 84 c0 74 0f 57 6a 02 57 8b 36 8b ce}  //weight: 1, accuracy: High
        $x_1_2 = "Main Invoked" ascii //weight: 1
        $x_1_3 = "regex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MX_2147925517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MX!MTB"
        threat_id = "2147925517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {29 ca 39 d0 7d 0c 81 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MX_2147925517_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MX!MTB"
        threat_id = "2147925517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 09 53 e8 6e 85 ff ff 59 33 db 57}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_MX_2147925517_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.MX!MTB"
        threat_id = "2147925517"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 c0 75 08 6a 1c e8 22 01 00 00 59 e8 d5 25 00 00 85 c0 75 08 6a 10 e8 11 01 00 00 59}  //weight: 1, accuracy: High
        $x_1_2 = {59 85 c0 74 07 50 e8 ea fb ff ff 59 e8 f1 68 00 00 56 50 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Bayrob_AMX_2147939133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.AMX!MTB"
        threat_id = "2147939133"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 e8 76 17 00 00 59 e8 d0 06 00 00 0f b7 c0 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_NIT_2147945689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.NIT!MTB"
        threat_id = "2147945689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ba 49 ab ff ff 66 89 15 ?? ?? ?? 00 8a 17 30 11 dd 05 ?? ?? ?? 00 d8 c1 41 47 dc 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 3b c8 75 d6}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 72 08 8b 1c 37 89 1c 8e 8b 72 04 bb 01 00 00 00 03 cb 2b f0 83 c7 04 3b ce 7c e4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Bayrob_NIT_2147945689_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bayrob.NIT!MTB"
        threat_id = "2147945689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bayrob"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {e8 7c 31 ff ff 6a 02 5e 89 30 e8 3e 31 ff ff 89 30 e9 d2 03 00 00 66 83 7b 02 3a 75 1d 0f b7 03 66 85 c0 74 06 66 39 73 04 74 d5 50 e8 0f ef ff ff}  //weight: 3, accuracy: High
        $x_2_2 = {89 b5 b0 fb ff ff 89 b5 b4 fb ff ff e8 63 82 00 00 83 c4 1c 89 47 1c 89 47 18 89 47 20 e9 31 02 00 00 39 b5 90 fb ff ff 0f 84 c8 fe ff ff ff b5 90 fb ff ff e8 1c 16 ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

