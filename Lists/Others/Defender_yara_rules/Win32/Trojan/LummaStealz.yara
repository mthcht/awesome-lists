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

rule Trojan_Win32_LummaStealz_AA_2147936645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LummaStealz.AA!MTB"
        threat_id = "2147936645"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LummaStealz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 76 7a 40 f8 f0 f7 94 4d ce 88 ce 86 c8 67 18 55 63 c1 36 30 b8 39 ba aa 22 90 b8 b9 ae 34 35 53 b4 42 d7 d4 6e c7 cd 60 ff 16 a9 3c b2 51 bf 28 3e 79 3b 28 c0 c7 2a 3d c6 66 31 24 8a ca 57 34 cd cd d7 c1}  //weight: 1, accuracy: High
        $x_1_2 = {b0 9a eb 52 7c d3 2c bd ab 16 93 3a 3d af 64 c6 26 76 c9 67 e3 16 5d 18 0a 0c 8f f6 c1 5a cd d9 17 2b d1 06 45 f4 81 d3 2e 77 7c e8 6e 87 6a 7f e6 b0 9f cb 57 42 e5 70 6c 44 5f 5a 1b 88 a9 9b 78 1e 10 07 47 9b f1 a4 60 a8 ea 83 1c 5b ef 50 12 3e 20 a2 99 e7 ae 39 a8 40 16 99 80 5d 83 70 7c e8 70 fa 6a a5 ee b8 16 96 13 1a 2c 05 80 a0 ca bd 93 4d e0 12 0a ae aa cf f3 12 a7 30 fe 60 c6 37 36 1d 77 20 44 39 a9 a2 47 82 2a d4 39 82 cc 57 fe 66 64 7e 98 78 e4 24 e6 d8 b0 df 22 fe 41 74 a0 27 dc a0 ec c9 b2 8a 0e c6 de cc 1c 95 63 87 b2 2f bc f2 0f a4 59 09 92}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

