rule Trojan_Win32_Paramis_A_2147643229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Paramis.A"
        threat_id = "2147643229"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Paramis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 03 4d ?? 0f be 51 01 8b 45 ?? 0f be 88 ?? ?? ?? ?? 33 d1 8b 45 ?? 03 45 ?? 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {47 6f 6f 67 6c 65 20 54 6f 6f 6c 62 61 72 00 00 47 45 54 00 79 61 68 6f 6f 2e 63 6f 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Paramis_B_2147643230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Paramis.B"
        threat_id = "2147643230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Paramis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 08 03 8d ?? ?? ff ff 0f be 51 01 8b 85 ?? ?? ff ff 0f be 88 ?? ?? ?? ?? 33 d1 8b 85 ?? ?? ff ff 03 85 ?? ?? ff ff 88 10}  //weight: 1, accuracy: Low
        $x_1_2 = {47 6f 6f 67 6c 65 20 54 6f 6f 6c 62 61 72 00 00 47 45 54 00 79 61 68 6f 6f 2e 63 6f 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Paramis_C_2147643231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Paramis.C"
        threat_id = "2147643231"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Paramis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 ?? ?? ?? ff ff 0f be ?? 01 8b ?? ?? ?? ff ff 0f be ?? ?? ?? ?? ?? 33 c8 8b 95 ?? ?? ff ff 03 95 ?? ?? ff ff 88 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {47 6f 6f 67 6c 65 20 54 6f 6f 6c 62 61 72 00 00 47 45 54 00 79 61 68 6f 6f 2e 63 6f 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Paramis_D_2147643232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Paramis.D"
        threat_id = "2147643232"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Paramis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 08 03 ?? ?? 0f be ?? 01 8b ?? ?? 0f be ?? ?? ?? ?? ?? 33 ?? 8b ?? ?? 03 ?? ?? 88}  //weight: 1, accuracy: Low
        $x_1_2 = {47 6f 6f 67 6c 65 20 54 6f 6f 6c 62 61 72 00 00 47 45 54 00 79 61 68 6f 6f 2e 63 6f 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Paramis_E_2147643233_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Paramis.E"
        threat_id = "2147643233"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Paramis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 08 03 55 ?? 0f be ?? 01 8b 4d ?? 0f be ?? ?? ?? ?? ?? 33 c2 8b 4d ?? 03 4d ?? 88 01}  //weight: 1, accuracy: Low
        $x_1_2 = {47 6f 6f 67 6c 65 20 54 6f 6f 6c 62 61 72 00 00 47 45 54 00 79 61 68 6f 6f 2e 63 6f 6d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

