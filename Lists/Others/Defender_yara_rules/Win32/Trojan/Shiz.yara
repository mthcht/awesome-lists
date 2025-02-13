rule Trojan_Win32_Shiz_AS_2147839751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shiz.AS!MTB"
        threat_id = "2147839751"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d1 29 15 f2 f0 41 00 d1 ca 2b 15 e0 f4 41 00 42 c1 c2 06 4a d1 ca 29 15 59 ff 41 00 89 1d d7 fc 41 00 8b 15 d7 fc 41 00 81 fa 1c 80 d3 81}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shiz_RG_2147893257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shiz.RG!MTB"
        threat_id = "2147893257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 cc d6 14 00 5a b9 50 49 2c 00 03 d1 52 33 db 53 ff 15 b0 c0 41 00 33 c0 a3 37 20 41 00 33 c9 c1 c1 06 49 2b c9 03 0d 28 20 41 00 41 c1 c1 05 81 e9 02 06 00 00 73 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shiz_EM_2147928062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shiz.EM!MTB"
        threat_id = "2147928062"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shiz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {33 dd be 33 1d 00 00 03 ee d1 e5 d1 c5 bb 23 1d 00 00 03 eb 45 33 f5}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

