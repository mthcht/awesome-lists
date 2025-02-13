rule Trojan_Win32_Sfone_RD_2147852788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sfone.RD!MTB"
        threat_id = "2147852788"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 72 92 e7 7a cf 4b 7e 35 cb 3f be 15 e4 78 98 38 c7 b9 fb 49 07 2d 61 80 73 6b b2 c9 5a d5 27}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sfone_RE_2147888276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sfone.RE!MTB"
        threat_id = "2147888276"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {34 53 4d 47 41 3b d3 34 4d d3 35 2f 29 23 1d 6b d3 34 4d 17 11 0b 05 ff e5 0b 4d d3 34 9d 03 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sfone_RG_2147895654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sfone.RG!MTB"
        threat_id = "2147895654"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {cb c2 3f 78 9e 06 fd 29 76 ca 57 f9 f5 04 18 c5 7f 93 b5 3f 09 c0 b2 67 b0 0f 4e 28 01 1d b0 11 dc 95 ad 44 03 25 d2 d7 07 8a a1 6f d3 a0 f4 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Sfone_KAA_2147901609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sfone.KAA!MTB"
        threat_id = "2147901609"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 0d 83 c2 01 83 c1 01 eb ec 19 c0 83 d8 ff 85 c0 0f 84 9c 00 00 00 b9 80 6f 41 00 ba e0 c9 40}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

