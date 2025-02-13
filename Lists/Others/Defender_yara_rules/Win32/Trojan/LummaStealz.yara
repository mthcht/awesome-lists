rule Trojan_Win32_LummaStealz_B_2147919034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealz.B!MTB"
        threat_id = "2147919034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lid=%s&j=%s&ver=" ascii //weight: 1
        $x_1_2 = {38 39 ca 83 e2 03 8a 54 14 08 32 54 0d 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealz_DA_2147923630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealz.DA!MTB"
        threat_id = "2147923630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 0f b7 16 83 c6 02 66 85 d2 75 ef 66 c7 00 00 00 0f b7 11}  //weight: 1, accuracy: High
        $x_1_2 = {0c 0f b7 4c 24 04 66 89 0f 83 c7 02 39 f7 73 0c 01 c3 39 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealz_DC_2147923631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealz.DC!MTB"
        threat_id = "2147923631"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 a5 8b 74 24 f8 8b 7c 24 f4 8d 54 24 04 ff 54 24 fc c3}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 48 8b 4c 24 48 0f b6 8c 0c e0 00 00 00 89 c2 83 c2 5a 21 ca 01 c8 01 d2 29 d0 05 5a 60 05 a7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_LummaStealz_DD_2147923632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealz.DD!MTB"
        threat_id = "2147923632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "c2sock" ascii //weight: 1
        $x_1_2 = "c2conf" ascii //weight: 1
        $x_1_3 = "lid=%s" ascii //weight: 1
        $x_1_4 = {2f 4c 75 6d [0-60] 43 32 [0-32] 42 75 69 6c 64}  //weight: 1, accuracy: Low
        $x_1_5 = "TeslaBrowser" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

