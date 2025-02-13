rule Trojan_Win32_SmkLdr_H_2147753912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmkLdr.H!MTB"
        threat_id = "2147753912"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmkLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "_gat=" wide //weight: 2
        $x_2_2 = "__io=" wide //weight: 2
        $x_2_3 = "Cookie: __gads=" wide //weight: 2
        $x_1_4 = "GET" wide //weight: 1
        $x_1_5 = "POST" wide //weight: 1
        $x_1_6 = "url(\"" ascii //weight: 1
        $x_1_7 = "src=\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SmkLdr_B_2147762897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmkLdr.B!MTB"
        threat_id = "2147762897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmkLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 00 98 40 38 18 75 f8}  //weight: 1, accuracy: High
        $x_1_2 = {66 01 08 8d 40 02 66 39 18 75 f0 05 00 b9 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SmkLdr_A_2147762999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmkLdr.A!MTB"
        threat_id = "2147762999"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmkLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {64 a1 30 00 00 00 8b f0 8a 40 02 84 c0 75 16 8b 46 68 83 e0 70 85 c0 75 0c 8b 46 18 8b 40 10 85 c0}  //weight: 10, accuracy: High
        $x_1_2 = {80 00 98 40 38 18 75 f8}  //weight: 1, accuracy: High
        $x_1_3 = {66 01 08 8d 40 02 66 39 18 75 f0 05 00 b9 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5a eb 0c 03 ca 68 00 80 00 00 6a 00 57 ff 11 8b c6 5a 5e 5f 59 5b 5d ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_SmkLdr_E_2147763089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SmkLdr.E!MTB"
        threat_id = "2147763089"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SmkLdr"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b f0 8a 40 02 84 c0 75 ?? 8b 46 68 83 e0 70 85 c0 75 0c 8b 46 18 8b 40 10 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {5a eb 0c 03 ca 68 00 80 00 00 6a 00 57 ff 11 8b c6 5a 5e 5f 59 5b 5d ff e0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

