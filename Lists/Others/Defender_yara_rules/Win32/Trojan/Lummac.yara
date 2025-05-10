rule Trojan_Win32_Lummac_GA_2147916810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.GA!MTB"
        threat_id = "2147916810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {ce 31 c4 cf c7 40 ?? 3a cd fe cb c7 40 ?? 36 c9 3c c7 c7 40 ?? 32 c5 c4 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lummac_BZ_2147927285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.BZ!MTB"
        threat_id = "2147927285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 44 24 0c 83 6c 24 ?? ?? 83 6c 24 ?? ?? 8a 44 24 ?? 30 04 2f 83 fb 0f 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lummac_BZ_2147927285_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.BZ!MTB"
        threat_id = "2147927285"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 40 05 00 00 10 00 00 00 58 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 72 73 72 63 00 00 00 b0 02 00 00 00 50 05 00 00 02 00 00 00 68 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lummac_SC_2147931978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.SC"
        threat_id = "2147931978"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b0 40 c3 b0 3f c3 89 c8 04 d0 3c 09 77 06 80 c1 04 89 c8 c3}  //weight: 10, accuracy: High
        $x_10_2 = {b0 40 c3 b0 3f c3 80 f9 30 72 ?? 80 f9 39 77 06 80 c1 04 89 c8 c3}  //weight: 10, accuracy: Low
        $x_10_3 = {8b 4c 24 04 8b 14 24 31 ca f7 d2 21 ca 29 d0}  //weight: 10, accuracy: High
        $x_10_4 = {89 f1 c1 e9 0c 80 c9 e0 88 08 89 f1 c1 e9 06 80 e1 3f 80 c9 80 88 48 01 80 e2 3f}  //weight: 10, accuracy: High
        $x_5_5 = {02 0f b7 16 83 c6 02 66 85 d2 75 ef 66 c7 00 00 00 0f b7 11}  //weight: 5, accuracy: High
        $x_5_6 = {0c 0f b7 4c 24 04 66 89 0f 83 c7 02 39 f7 73 0c 01 c3 39 eb}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Lummac_SD_2147933009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.SD"
        threat_id = "2147933009"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {32 1d 30 f9 48 77 82 5a 3c bf 73 7f dd 4f 15 75}  //weight: 5, accuracy: High
        $x_5_2 = {00 6e 75 6c 6c 00 74 72 75 65 00 66 61 6c 73 65 00 30 31 32 33 34 35 36 37 38 39 41 42 43 44 45 46 47 48 49 4a 4b 4c 4d 4e 4f 50 51 52 53 54 55 56 57 58 59 5a}  //weight: 5, accuracy: High
        $x_5_3 = {fe dc ba 98 76 54 32 10 f0 e1 d2 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lummac_SE_2147933324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.SE"
        threat_id = "2147933324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 44 24 08 8b 54 24 04 89 54 24 fc 89 74 24 f8 89 7c 24 f4 8b 4c 24 0c 8d 74 24 10 8d 7c 24 04 f3 a4 8b 74 24 f8 8b 7c 24 f4 8d 54 24 04 ff 54 24 fc c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lummac_EAZK_2147936811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.EAZK!MTB"
        threat_id = "2147936811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {33 45 fc 89 45 e8 8b 4d fc c1 e1 10 33 4d e8 89 4d fc 8b 55 f8 83 c2 04 89 55 f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lummac_PGL_2147937134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.PGL!MTB"
        threat_id = "2147937134"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {33 55 fc 89 55 e8 8b 45 fc c1 e0 ?? 33 45 e8 89 45 fc 8b 4d f8 83 c1 ?? 89 4d f8 8b 55 fc c1 ea ?? 03 55 fc 89 55 fc eb b2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lummac_SDA_2147939400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.SDA"
        threat_id = "2147939400"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {32 1d 30 f9 48 77 82 5a 3c bf 73 7f dd 4f 15 75}  //weight: 5, accuracy: High
        $x_5_2 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" ascii //weight: 5
        $x_5_3 = {57 58 59 5a 00 78 58 00}  //weight: 5, accuracy: High
        $x_5_4 = {fe dc ba 98 76 54 32 10 f0 e1 d2 c3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lummac_SDB_2147941106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lummac.SDB"
        threat_id = "2147941106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lummac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "buy now: tg @lummanowork" ascii //weight: 1
        $x_1_2 = "buy&sell logs: @lummamarketplace_bot" ascii //weight: 1
        $x_1_3 = "lummac2 build:" ascii //weight: 1
        $x_1_4 = "configuration:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

