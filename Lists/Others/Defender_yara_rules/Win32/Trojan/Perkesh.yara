rule Trojan_Win32_Perkesh_A_2147616756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Perkesh.gen!A"
        threat_id = "2147616756"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Perkesh"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 0d 3d 02 01 00 00 75 57 83 7e 08 0d 75 51 57 6a 40 59 c6 85 fc fe ff ff 00 33 c0 8d bd fd fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {bf a8 b0 cd cb b9 bb f9 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 4e 4f 44 33 32 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 00 55 53 45 52 33 32 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = "callnexthookex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Perkesh_A_2147616773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Perkesh.A"
        threat_id = "2147616773"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Perkesh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 10 6a 03 ff 15 ?? ?? 00 10 a3 ?? ?? 00 10 6a 64 ff 15 ?? ?? 00 10 eb f6}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 46 04 3d 01 02 00 00 74 14 3d 02 02 00 00 74 0d 3d 02 01 00 00 75 ?? 83 7e 08 0d}  //weight: 2, accuracy: Low
        $x_1_3 = {bd f0 c9 bd b6 be b0 d4 00}  //weight: 1, accuracy: High
        $x_1_4 = {33 36 30 b0 b2 c8 ab ce c0 ca bf 00 c8 f0 d0 c7 00}  //weight: 1, accuracy: High
        $x_1_5 = {c8 f0 d0 c7 00}  //weight: 1, accuracy: High
        $x_1_6 = {bf a8 b0 cd cb b9 bb f9 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Perkesh_A_2147851761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Perkesh.A!MTB"
        threat_id = "2147851761"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Perkesh"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 0c 33 8a c3 c0 e0 ?? 2c 1e 8b fe 02 c8 33 c0 88 0c 33 83 c9 ?? 43 f2 ae f7 d1 49 3b d9 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

