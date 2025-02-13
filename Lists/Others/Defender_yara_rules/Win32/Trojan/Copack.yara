rule Trojan_Win32_Copack_RPY_2147897204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copack.RPY!MTB"
        threat_id = "2147897204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 31 08 42 09 d3 40 4a 39 f8 75 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copack_RPY_2147897204_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copack.RPY!MTB"
        threat_id = "2147897204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 31 39 01 d3 4a 41 42 89 da 89 d2 39 c1 75 d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copack_RPY_2147897204_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copack.RPY!MTB"
        threat_id = "2147897204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 f8 09 ff e8 1c 00 00 00 29 c0 81 e8 01 00 00 00 31 16 81 e8 ?? ?? ?? ?? 46 01 c7 39 de 75 db 89 f8 29 c0 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copack_RPZ_2147897205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copack.RPZ!MTB"
        threat_id = "2147897205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c3 81 ee 01 00 00 00 8d 14 13 4e 21 f6 01 c9 8b 12}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copack_RPZ_2147897205_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copack.RPZ!MTB"
        threat_id = "2147897205"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 31 89 df 81 c1 04 00 00 00 81 c2 ?? ?? ?? ?? 39 c1 75 e7 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copack_RPX_2147900122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copack.RPX!MTB"
        threat_id = "2147900122"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copack"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 1c 24 83 c4 04 e8 25 00 00 00 01 c7 21 c7 31 1e 68 ?? ?? ?? ?? 58 46 21 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

