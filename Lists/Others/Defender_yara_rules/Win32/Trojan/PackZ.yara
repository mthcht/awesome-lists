rule Trojan_Win32_PackZ_KAA_2147851489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PackZ.KAA!MTB"
        threat_id = "2147851489"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PackZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {49 8b 30 81 e9 ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 81 e6 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 31 32 29 f9 bb 5e 06 5d b6 42 09 fb 81 c1 ?? ?? ?? ?? 40 21 c9 89 d9 81 fa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PackZ_KAB_2147852432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PackZ.KAB!MTB"
        threat_id = "2147852432"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PackZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 19 29 fa 81 ef ?? ?? ?? ?? 29 f8 81 e3 ?? ?? ?? ?? f7 d7 f7 d7 81 ef ?? ?? ?? ?? 31 1e ba ?? ?? ?? ?? f7 d0 89 c7 46 42 42 81 c2 ?? ?? ?? ?? 41 09 c2 09 f8 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PackZ_AMAA_2147890139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PackZ.AMAA!MTB"
        threat_id = "2147890139"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PackZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 cb 41 8d 3c 07 bb ?? ?? ?? ?? 89 cb 8b 3f 21 c9 01 d9 21 db 81 e7 ff 00 00 00 81 c3 ?? ?? ?? ?? b9 ?? ?? ?? ?? 81 c3 01 00 00 00 40 09 cb 81 e9 ?? ?? ?? ?? 81 f8 f4 01 00 00 75 ?? b8 00 00 00 00 81 c3 01 00 00 00 21 c9 49 01 db 29 d9 4b 31 3a 89 cb bb ?? ?? ?? ?? 81 c2 02 00 00 00 89 d9 29 cb 81 e9 ?? ?? ?? ?? 39 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 07 09 d9 09 c9 88 06 21 cb 09 c9 bb ?? ?? ?? ?? 46 81 c1 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 81 c3 01 00 00 00 81 c7 02 00 00 00 01 cb 43 39 d7 0f 8e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PackZ_KAC_2147890151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PackZ.KAC!MTB"
        threat_id = "2147890151"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PackZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 03 81 ea ?? ?? ?? ?? 21 d7 81 e0 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 f9 31 06 21 c9 4a 81 c6 ?? ?? ?? ?? f7 d7 01 d2 43 21 f9 29 d1 81 fe}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PackZ_KAD_2147892119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PackZ.KAD!MTB"
        threat_id = "2147892119"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PackZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 1a 21 f9 f7 d7 81 e3 ?? ?? ?? ?? f7 d1 81 c6 ?? ?? ?? ?? 31 18 81 c7 ?? ?? ?? ?? 21 c9 21 fe 81 c0 ?? ?? ?? ?? 29 f1 81 e9 ?? ?? ?? ?? 21 f7 42 89 f1 81 c1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PackZ_KAE_2147892123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PackZ.KAE!MTB"
        threat_id = "2147892123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PackZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 cb 81 eb ?? ?? ?? ?? 8b 32 bf ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 81 e6 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? bf ?? ?? ?? ?? 89 cf 31 30 09 ff 49 40 41 f7 d1 4b 81 c2 ?? ?? ?? ?? 21 cf f7 d7}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PackZ_KAJ_2147892126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PackZ.KAJ!MTB"
        threat_id = "2147892126"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PackZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 1e 21 d2 21 c2 89 c2 81 e3 ?? ?? ?? ?? 29 d1 81 ea ?? ?? ?? ?? 49 31 1f b8 ?? ?? ?? ?? 21 c9 47 09 d0 89 d0 46 f7 d2 29 d0 21 d2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PackZ_AMAB_2147892790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PackZ.AMAB!MTB"
        threat_id = "2147892790"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PackZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 10 f7 d1 09 c9 81 c7 ?? ?? ?? ?? 81 e2 ff 00 00 00 f7 d7 49 81 e9 ?? 00 00 00 31 16 21 f9 49 46 01 f9 09 fb 81 c3 ?? ?? ?? ?? 40 21 c9 09 db 09 df 81 fe ?? ?? ?? ?? 0f 8c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PackZ_KAK_2147896275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PackZ.KAK!MTB"
        threat_id = "2147896275"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PackZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 37 49 21 c1 81 e6 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 4a 01 c9 31 33 21 d1 48 f7 d2 43 b8 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 29 c2 47 29 c8 01 d2 f7 d1 81 fb 92 9c 65 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PackZ_KAM_2147896279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PackZ.KAM!MTB"
        threat_id = "2147896279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PackZ"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 3a 81 c0 ?? ?? ?? ?? bb ?? ?? ?? ?? 01 c1 81 e7 ?? ?? ?? ?? 48 b9 ?? ?? ?? ?? 31 3e 29 c8 f7 d1 81 c6 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 89 cb b9 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? f7 d3 b8 ?? ?? ?? ?? 09 c0 81 fe}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

