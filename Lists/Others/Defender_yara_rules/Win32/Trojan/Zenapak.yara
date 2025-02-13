rule Trojan_Win32_Zenapak_CCCJ_2147892629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenapak.CCCJ!MTB"
        threat_id = "2147892629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 00 65 00 65 00 64 00 6e 00 73 00 65 00 61 00 73 00 6f 00 6e 00 73}  //weight: 1, accuracy: High
        $x_1_2 = {66 00 72 00 75 00 69 00 74 00 66 00 75 00 6c 00 2e 00 67 00 6f 00 64 00 58 00 67 00 72 00 65 00 61 00 74 00 65 00 72}  //weight: 1, accuracy: High
        $x_1_3 = {77 00 68 00 69 00 63 00 68 00 73 00 67 00 61 00 74 00 68 00 65 00 72 00 65 00 64 00 6a 00 66 00 72 00 75 00 69 00 74 00 75 00 43 00 61 00 74 00 74 00 6c 00 65 00 61 00 6c 00 73 00 6f 00 69}  //weight: 1, accuracy: High
        $x_1_4 = {66 00 65 00 6d 00 61 00 6c 00 65 00 73 00 61 00 69 00 64 00 4c 00 36 00 68 00 48}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenapak_CCCK_2147892640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenapak.CCCK!MTB"
        threat_id = "2147892640"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 00 61 00 72 00 74 00 68 00 6d 00 61 00 6e 00 75 00 34 00 73 00 69 00 78 00 74 00 68 00 79 00 69 00 65 00 6c 00 64 00 69 00 6e 00 67 00 6d 00 36}  //weight: 1, accuracy: High
        $x_1_2 = {54 00 73 00 65 00 61 00 73 00 59 00 42 00 75 00 6e 00 64 00 65 00 72 00 45}  //weight: 1, accuracy: High
        $x_1_3 = {75 00 6e 00 74 00 6f 00 66 00 69 00 66 00 74 00 68 00 6e 00 69 00 67 00 68 00 74}  //weight: 1, accuracy: High
        $x_1_4 = {6b 00 69 00 6e 00 64 00 73 00 65 00 63 00 6f 00 6e 00 64 00 39 00 4d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenapak_CCCQ_2147893066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenapak.CCCQ!MTB"
        threat_id = "2147893066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lifeqgod" wide //weight: 1
        $x_1_2 = "hathtZqeZoverhRyears" wide //weight: 1
        $x_1_3 = "CcreatureMwereD02moving" wide //weight: 1
        $x_1_4 = "sVUnderfirmament" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenapak_CCDI_2147894771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenapak.CCDI!MTB"
        threat_id = "2147894771"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 da 81 c2 ?? ?? ?? ?? 0f b7 12 31 f2 8b b5 ?? ?? ?? ?? 01 ce 89 34 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenapak_CCDZ_2147896557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenapak.CCDZ!MTB"
        threat_id = "2147896557"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b7 c7 0f b7 ce 31 d8 8b 9d ?? ?? ?? ?? 31 d9 8b 9d ?? ?? ?? ?? 01 d8 8b 9d ?? ?? ?? ?? 01 d9 81 c2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Zenapak_CCEN_2147897374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Zenapak.CCEN!MTB"
        threat_id = "2147897374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Zenapak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 c2 81 c2 ?? ?? ?? ?? 8b 03 0f b7 12 31 c2 01 ca 81 fe ?? ?? ?? ?? 89 d0 89 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

