rule Trojan_Win32_Dofoil_AB_2147726216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.AB"
        threat_id = "2147726216"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "auth_swith" ascii //weight: 1
        $x_1_2 = "auth_login" ascii //weight: 1
        $x_1_3 = "Host: %s" ascii //weight: 1
        $x_10_4 = "idle_%d" ascii //weight: 10
        $x_10_5 = "exception/detail/exception_ptr.hpp" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dofoil_DSK_2147742752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.DSK!MTB"
        threat_id = "2147742752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {88 45 fc 8a 06 0c 01 0f b6 f8 89 d8 99 f7 ff 0f b6 3e 01 f8 88 01 8a 45 fc}  //weight: 2, accuracy: High
        $x_2_2 = {88 3e d2 e0 88 07 eb ?? 89 d7 8a 00 0c 01 0f b6 c8 89 d8 99 f7 f9 0f b6 0e 01 c8 8a 0f 88 dc 88 cf d2 e4 00 e7 88 d9 eb d7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Dofoil_PDSK_2147743913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.PDSK!MTB"
        threat_id = "2147743913"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 fc 33 45 dc 89 45 fc c7 05 ?? ?? ?? ?? f4 6e e0 f7 8b 4d fc 33 4d f8 89 4d f8 8b 55 f4 2b 55 f8 89 55 f4 81 3d ?? ?? ?? ?? d9 02 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dofoil_VSD_2147751452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.VSD!MTB"
        threat_id = "2147751452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 c7 81 3d ?? ?? ?? ?? 21 06 00 00 a3 ?? ?? ?? ?? 75 12 00 a1 ?? ?? ?? ?? 0f b6 80 ?? ?? ?? ?? 03 05}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 37 4e 79 05 00 e8}  //weight: 1, accuracy: Low
        $x_2_3 = {8b f5 c1 ee 05 03 74 24 34 33 c7 81 3d ?? ?? ?? ?? b4 11 00 00 89 44 24 10 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dofoil_STA_2147767010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.STA"
        threat_id = "2147767010"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 11 00 00 c7 [0-6] 1c 37 ef c6}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 c3 66 6d c7 [0-6] ba 48 f5 62 c7 [0-6] 02 9e 92 29 c7 [0-6] 56 c1 16 6e}  //weight: 1, accuracy: Low
        $x_1_3 = {d3 e0 c1 ea 05 03 [0-6] 03 [0-6] 89 ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_2_4 = {6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 78 00 61 00 74 00 65 00 70 00 61 00 00 00 00 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c 00 00 00 00 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Dofoil_VH_2147773225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.VH!MSR"
        threat_id = "2147773225"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rodevan. Lufeyaluwahob tam xak kafodagibubus wuyovimu. Gave. Tezumesexogojo. Petuxuwo." ascii //weight: 1
        $x_1_2 = "hurugamesapoxugiko" ascii //weight: 1
        $x_1_3 = "VOYODELORUVALIXEKECOROCUBEJUGIBE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dofoil_RT_2147784860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.RT!MTB"
        threat_id = "2147784860"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 14 03 e8 ?? ?? ?? ?? 30 02 57 ff d6 57 ff 15 ?? ?? ?? ?? 57 57 57 ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 57 ff 15 ?? ?? ?? ?? 43 3b ?? ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dofoil_DA_2147808446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.DA!MTB"
        threat_id = "2147808446"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 e1 f1 22 66 89 8c 24 ?? ?? ?? ?? 8b 94 24 ?? ?? ?? ?? 8b b4 24 ?? ?? ?? ?? 66 89 84 24 ?? ?? ?? ?? 8a 1c 16 8b 94 24 ?? ?? ?? ?? 8b b4 24 ?? ?? ?? ?? 88 1c 16 66 8b 84 24 ?? ?? ?? ?? 66 35 1a 1e 66 89 84 24 ?? ?? ?? ?? 8b 8c 24 ?? ?? ?? ?? 8b 54 24 ?? 01 d1 89 8c 24 ?? ?? ?? ?? e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dofoil_CM_2147811659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.CM!MTB"
        threat_id = "2147811659"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 45 6c 89 45 68 8b 85 90 fe ff ff 01 45 68 8b 45 6c c1 e8 05 89 45 70 8b 45 70 33 7d 68 8b 8d 80 fe ff ff 03 c1 33 c7}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dofoil_NC_2147813560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.NC!MTB"
        threat_id = "2147813560"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {55 8b ec 51 83 65 fc 00 8b 45 0c 89 45 fc 8b 45 08 31 45 fc 8b 45 fc 89 01 c9 c2 08 00 55 8b ec 51 83 65 fc 00 8b 45 0c 01 45 fc 8b 45 fc 31 45 08 8b 45 08 c9 c2 08 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dofoil_ASN_2147893164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.ASN!MTB"
        threat_id = "2147893164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 f1 89 4d d0 89 f0 89 45 cc 89 f9 80 c9 01 99 f7 f9 89 45 c4}  //weight: 1, accuracy: High
        $x_1_2 = "c>gtq tc >vnfer>e>eu>r/seeret kete tseu vdluPete<>cat lsrsyee>ee tEr lii dtiios" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dofoil_MMZ_2147956779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dofoil.MMZ!MTB"
        threat_id = "2147956779"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dofoil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {99 f7 7d dc 8b 45 10 8b 00 2b 50 14 8b 41 0c 0f b6 04 10 89 45 e8 8b 45 0c 8b 00 8b 4d 0c 8b 09 8b 55 e4 2b 51 14 8b 40 0c 0f b6 ?? 10 33 4d e8 e8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

