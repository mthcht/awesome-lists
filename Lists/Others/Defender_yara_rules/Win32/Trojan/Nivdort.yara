rule Trojan_Win32_Nivdort_A_2147707846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nivdort.A!dll"
        threat_id = "2147707846"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 78 07 45 75 0e 80 78 08 58 75 08 80 78 09 45 75 02}  //weight: 2, accuracy: High
        $x_1_2 = {83 e9 05 c6 04 08 32 8d 85 ?? ?? ff ff 50 ff 15}  //weight: 1, accuracy: Low
        $x_1_3 = {c6 45 f0 49 c6 45 f1 45 c6 45 f2 58 c6 45 f3 50 c6 45 f4 4c c6 45 f5 4f c6 45 f6 52 c6 45 f7 45}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 e0 46 c6 45 e1 49 c6 45 e2 52 c6 45 e3 45 c6 45 e4 46 c6 45 e5 4f c6 45 e6 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Nivdort_B_2147707847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nivdort.B!dll"
        threat_id = "2147707847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 60 ea 00 00 ff 15 ?? ?? 40 00 eb f3}  //weight: 1, accuracy: Low
        $x_1_2 = {57 ff d6 85 c0 74 f0 57 ff d3 85 c0 75 07 6a 03 58}  //weight: 1, accuracy: High
        $x_1_3 = {48 6f 6f 6b 44 6f 6e 65 00 00 00 00 48 6f 6f 6b 49 6e 69 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nivdort_ND_2147913123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nivdort.ND!MTB"
        threat_id = "2147913123"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nivdort"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 c8 ff e9 c8 0a ?? ?? f6 46 0c 40 75 ?? 56 e8 55 0c ?? ?? 59 ba 28 67 ?? ?? 83 f8 ff 74}  //weight: 3, accuracy: Low
        $x_3_2 = {c1 e1 06 03 0c b5 60 84 42 00 eb ?? 8b ca f6 41 24 7f}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

