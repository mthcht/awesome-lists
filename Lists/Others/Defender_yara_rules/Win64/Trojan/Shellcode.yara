rule Trojan_Win64_Shellcode_AMMH_2147909692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shellcode.AMMH!MTB"
        threat_id = "2147909692"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 01 d0 44 0f b6 00 8b 85 ?? ?? ?? ?? 48 98 0f b6 4c 05 ?? 8b 85 ?? ?? ?? ?? [0-11] 48 01 d0 44 89 c2 31 ca 88 10 83 85 ?? ?? ?? ?? 01 83 85 ?? ?? ?? ?? 01 8b 85 ?? ?? ?? ?? 48 98 48 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shellcode_MX_2147948455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shellcode.MX!MTB"
        threat_id = "2147948455"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 31 ca 48 31 c9 48 ff c8 88 02 48 31 fa 48 ff c3 48 39 f3}  //weight: 1, accuracy: High
        $x_1_2 = "hello_im_sii" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shellcode_PGSH_2147959688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shellcode.PGSH!MTB"
        threat_id = "2147959688"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {89 d9 c1 f9 ?? 29 ca 44 8d 0c d2 46 8d 0c 4a 89 da 44 29 ca 48 63 d2 0f b6 14 16 41 30 10 48 69 c0 ?? ?? ?? ?? 48 c1 f8 ?? 29 c8 69 c0 ?? ?? ?? ?? 39 d8 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shellcode_LDG_2147966282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shellcode.LDG!MTB"
        threat_id = "2147966282"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 8b c8 b8 ?? ?? ?? ?? 41 f7 e0 41 8b c0 41 ff c0 2b c2 d1 e8 03 c2 c1 e8 ?? 6b c0 ?? 2b c8 8a 4c 0d ?? 32 0b 48 ff c3 41 88 09 49 ff c1 44 3b c6 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Shellcode_GB_2147966654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shellcode.GB!MTB"
        threat_id = "2147966654"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shellcode"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 44 24 ?? 33 d2 48 8b 44 24 ?? 48 8b 4c 24 ?? 48 f7 f1 48 8b c2 48 8b d0 48 8d 8c 24 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0f b6 00 8b 4c 24 ?? 33 c8 8b c1 89 44 24 ?? 48 8b 54 24 ?? 48 8d 8c 24 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

