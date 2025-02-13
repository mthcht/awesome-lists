rule Trojan_Win32_BazarLoader_CN_2147768128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazarLoader.CN!MTB"
        threat_id = "2147768128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = ".bazar" ascii //weight: 20
        $x_1_2 = "Cannot read remote PEB: %lu" ascii //weight: 1
        $x_1_3 = "Process Doppelganging test!" ascii //weight: 1
        $x_1_4 = "net localgroup \"administrator" ascii //weight: 1
        $x_1_5 = "nltest /domain_trusts /all_trusts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_BazarLoader_AF_2147783959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazarLoader.AF!MTB"
        threat_id = "2147783959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8a 0b 03 c2 03 f8 8b c6 c1 e0 10 0f af d7 40 0f af c6 03 55 f8 03 c2 8b 55 fc 42 89 45 f8}  //weight: 10, accuracy: High
        $x_10_2 = {81 ec 58 07 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 ec 56 57 50 8d 45 f4 64 a3 00 00 00 00 8b 73 10 8d 85 08 f9 ff ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BazarLoader_AM_2147783960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazarLoader.AM!MTB"
        threat_id = "2147783960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {50 53 81 ec 80 05 00 00 a1 ?? ?? ?? ?? 33 c5 89 45 ec 56 57 50 8d 45 f4 64 a3 ?? ?? ?? ?? 8b 73 10 8d 85 08 fb ff ff}  //weight: 10, accuracy: Low
        $x_10_2 = {0f be c0 8d 76 01 83 e8 30 0f af c1 8d 0c 49 c1 e1 02 03 d0 8a 06 84 c0 75 e6 81 f2 00 10 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BazarLoader_DB_2147784174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazarLoader.DB!MTB"
        threat_id = "2147784174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b 1c 24 83 c3 0c 89 5c 24 20 8b 5c 24 20 8b 1b 89 1a 8b 1c 24}  //weight: 10, accuracy: High
        $x_10_2 = {8b 44 24 10 8b 4c 24 04 89 01 8b 44 24 24 8b 4c 24 20 89 01}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BazarLoader_CR_2147811255_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazarLoader.CR!MTB"
        threat_id = "2147811255"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "initBuffer" ascii //weight: 3
        $x_3_2 = "uninitBuffer" ascii //weight: 3
        $x_3_3 = "updateBuffer" ascii //weight: 3
        $x_3_4 = "EcfcgciawfspVgzfsltilqj" ascii //weight: 3
        $x_3_5 = "NmmwnludxXjcoaoSvhxobl" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BazarLoader_CM_2147811256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazarLoader.CM!MTB"
        threat_id = "2147811256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AllCould" ascii //weight: 3
        $x_3_2 = "EproyAklW" ascii //weight: 3
        $x_3_3 = "GreatTime" ascii //weight: 3
        $x_3_4 = "knntagstpvnwa" ascii //weight: 3
        $x_3_5 = "fxaowkhknntagsup" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BazarLoader_LKA_2147845151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazarLoader.LKA!MTB"
        threat_id = "2147845151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 10 00 00 68 ?? ?? 00 00 6a 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {78 61 6d 70 70 5c 68 74 64 6f 63 73 [0-240] 4c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BazarLoader_B_2147895587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BazarLoader.B!MTB"
        threat_id = "2147895587"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BazarLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 11 88 55 ?? 0f b6 45 ?? c1 f8 ?? 0f b6 4d ?? c1 e1 ?? 0b c1 0f b6 55 ?? 33 c2 8b 4d}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 45 dc 83 c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 89 55}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

