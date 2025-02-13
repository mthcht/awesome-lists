rule Trojan_Win32_LaplasClipper_C_2147848834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LaplasClipper.C!MTB"
        threat_id = "2147848834"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LaplasClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 f7 75 ?? 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ?? 8b 45 ?? 03 45 ?? 8a 08 88}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LaplasClipper_D_2147849876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LaplasClipper.D!MTB"
        threat_id = "2147849876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LaplasClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {f6 17 80 07 ?? fe 07 47 e2 f6}  //weight: 2, accuracy: Low
        $x_2_2 = {33 c2 83 c1 ?? a9 ?? ?? ?? ?? 74 0c 00 8b 01 ba ?? ?? ?? ?? 03 d0 83 f0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LaplasClipper_E_2147904536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LaplasClipper.E!MTB"
        threat_id = "2147904536"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LaplasClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 1c 0f f2}  //weight: 2, accuracy: High
        $x_2_2 = {8d 1c 23 f2 04 00 83 34 24}  //weight: 2, accuracy: Low
        $x_2_3 = {23 c3 8b c9}  //weight: 2, accuracy: High
        $x_2_4 = {f7 d0 c1 cb}  //weight: 2, accuracy: High
        $x_2_5 = {8b 1c 24 c1 e6}  //weight: 2, accuracy: High
        $x_2_6 = {8d 0c 21 0f ba f0}  //weight: 2, accuracy: High
        $x_2_7 = {8d 1c 23 23 c1}  //weight: 2, accuracy: High
        $x_2_8 = {89 0c 24 8d 1c 23}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LaplasClipper_ALC_2147904906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LaplasClipper.ALC!MTB"
        threat_id = "2147904906"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LaplasClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 c2 31 c0 e8 ?? ?? ?? ?? 8d 05 9c f7 69 00 89 44 24 3c c7 44 24 40 07 00 00 00 8b 05 f8 15 88 00 8b 0d fc 15 88 00 89 44 24 44 89 4c 24 48}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

