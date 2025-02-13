rule Trojan_Win32_VBkrypt_GC_2147749080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBkrypt.GC!MTB"
        threat_id = "2147749080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBkrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 a0 00 00 [0-30] ff d0 [0-25] 8b 1c 0f [0-7] 31 f3 [0-8] 89 1c 08 [0-8] 83 e9 04 [0-10] 7d}  //weight: 1, accuracy: Low
        $x_1_2 = {68 00 b0 00 00 [0-30] ff d0 [0-25] 8b 1c 0f [0-7] 31 f3 [0-8] 89 1c 08 [0-8] 83 e9 04 [0-10] 7d}  //weight: 1, accuracy: Low
        $x_1_3 = {0f 77 89 1c 08 [0-8] 83 e9 04 [0-10] 7d [0-10] ff e0 46 00 ff d0 [0-25] 8b 1c 0f [0-7] 31 f3}  //weight: 1, accuracy: Low
        $x_1_4 = {89 1c 08 0f 77 [0-8] 83 e9 04 [0-10] 7d [0-10] ff e0 46 00 ff d0 [0-25] 8b 1c 0f [0-7] 31 f3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_VBkrypt_GD_2147749873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBkrypt.GD!MTB"
        threat_id = "2147749873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBkrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 f9 00 7d [0-25] ff d0 64 00 8b 14 0f [0-40] 31 f2 [0-10] 09 14 08 [0-25] 83 e9 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

