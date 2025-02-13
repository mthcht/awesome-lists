rule Trojan_Win32_Farfi_GPA_2147893342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfi.GPA!MTB"
        threat_id = "2147893342"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {33 d2 f7 75 10 b8 cd cc cc cc 80 c2 36 30 11 f7 65 0c 8b 4d 08 8b 45 0c 41 c1 ea 03 40 c7 45 08 00 00 00 00 89 45 0c 8d 14 92 03 d2 3b fa 8b 55 08 0f 45 d1 89 55 08 3b c3}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfi_GPB_2147895477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfi.GPB!MTB"
        threat_id = "2147895477"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {31 c9 89 c8 31 d2 f7 f6 0f b6 04 17 30 04 0b 83 c1 01 3b 4d}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfi_GNB_2147896246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfi.GNB!MTB"
        threat_id = "2147896246"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8b 5d 10 8b ce 83 e1 03 33 4d f8 8b 1c 8b 0f b6 4c 3e ff 33 d9 03 d8 0f b6 04 3e 33 d3 2b c2 4e 88 44 3e 01 0f b6 c0 75 b5}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Farfi_GPC_2147901081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Farfi.GPC!MTB"
        threat_id = "2147901081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Farfi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {6a 00 ff d6 90 90 8a 17 6a 00 32 d3 10 da 88 17 47 ff d6}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

