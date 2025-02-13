rule Backdoor_Win32_Coroxy_A_2147766831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coroxy.A"
        threat_id = "2147766831"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {b8 fc fd fe ff b9 40 00 00 00 ?? ?? ?? ?? ?? ?? ?? 2d 04 04 04 04}  //weight: 4, accuracy: Low
        $x_3_2 = {3c 19 74 20 3c 23 74 1c 3c 22 74 18 3c 2c 74 14 3c 2b 74 10 3c 43 74 0c 3c 3f 74 08 3c 40 74 04 3c 18}  //weight: 3, accuracy: High
        $x_1_3 = {2a d5 8b 14 ab a2 ce 11 b1 1f 00 aa 00 53 05 03}  //weight: 1, accuracy: High
        $x_1_4 = {68 04 00 00 98 ff 75 a0 e8 9e 3a 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 7e 66 04 80 ff 75 e8 e8 fb 1f 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {68 7f 66 04 40 ff 75 fc e8 71 3d 00 00}  //weight: 1, accuracy: High
        $x_1_7 = "-WindowStyle Hidden -ep bypass" ascii //weight: 1
        $x_1_8 = "/tor/server/fp/" ascii //weight: 1
        $x_1_9 = "BCryptEncrypt" ascii //weight: 1
        $x_1_10 = "onion-key" ascii //weight: 1
        $x_1_11 = "GET /tor/rendezvous2/%s HTTP/1.0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Coroxy_B_2147778287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coroxy.B"
        threat_id = "2147778287"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 7f 66 04 40 ff 75 fc e8}  //weight: 5, accuracy: High
        $x_5_2 = {b8 fc fd fe ff b9 40 00 00 00 ?? ?? ?? ?? ?? ?? ?? 2d 04 04 04 04}  //weight: 5, accuracy: Low
        $x_5_3 = "-WindowStyle Hidden -ep bypass" ascii //weight: 5
        $x_1_4 = "HOST1:149.28.10.250" ascii //weight: 1
        $x_1_5 = "HOST1:23.133.6.39" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Coroxy_E_2147821146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coroxy.E"
        threat_id = "2147821146"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {78 6f 72 64 75 ?? 81 3d ?? ?? ?? ?? 61 74 61 00 75 ?? 83 7d 10 00}  //weight: 10, accuracy: Low
        $x_10_2 = {81 3c 30 2e 62 69 74 0f 85}  //weight: 10, accuracy: High
        $x_10_3 = {66 b8 2e 00 aa 66 b8 65 00 aa 66 b8 78 00 aa 66 b8 65 00 aa b8 00 00 00 00}  //weight: 10, accuracy: High
        $x_5_4 = {8b 75 08 8b 7d 0c 32 c0 eb 03 a4 aa 49 0b c9 75 f9 8d 04 55 00 00 00 00}  //weight: 5, accuracy: High
        $x_5_5 = {33 c0 33 db 8a 1e 46 80 fb 30 72 0f 80 fb 39 77 0a 80 eb 30 f7}  //weight: 5, accuracy: High
        $x_5_6 = {8b 55 10 88 02 8a 07 30 02 ff 45 10 eb 02 30 07 49 83}  //weight: 5, accuracy: High
        $x_5_7 = {b8 fc fd fe ff b9 40 00 00 00 ?? ?? ?? ?? ?? ?? ?? 2d 04 04 04 04}  //weight: 5, accuracy: Low
        $x_2_8 = {8b 45 08 ab 8b 45 0c ab 8b 45 14 ab 8b 45 18 ab b8 01 00 00 00}  //weight: 2, accuracy: High
        $x_2_9 = {8b 08 8b 51 08 50 ff d2 8b 45 f8 8b 08 8b 51 08 50 ff d2 8b 45 fc 8b 08 8b 51 08 50 ff d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_10_*) and 4 of ($x_5_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Coroxy_F_2147821148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coroxy.F"
        threat_id = "2147821148"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 40 0c 8b 70 0c 8b 58 10 8b 36 8b 7e 30}  //weight: 1, accuracy: High
        $x_1_2 = {50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 06 6a 01 8d 45 ?? 50 e8}  //weight: 1, accuracy: Low
        $x_1_3 = {ba 00 01 00 00 81 c2 00 00 00 80 83 bd ?? ?? ?? ?? 04 75 ?? 81 c2 00 00 80 00 81 c2 00 10 00 00 81 c2 00 20 00 00 6a 00 52 6a 00 6a 00 6a 00 ff}  //weight: 1, accuracy: Low
        $x_1_4 = {50 68 04 00 00 98 ff 75 ?? e8}  //weight: 1, accuracy: Low
        $x_1_5 = {68 7e 66 04 80 ff 75 ?? e8}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 64 6a 00 8d 85 ?? ?? ff ff 50 6a 00 ff 75 ?? e8}  //weight: 1, accuracy: Low
        $x_1_7 = {0a 00 c6 45 ?? 05 c6 45 ?? 01 c6 45 ?? 00 c6 45 ?? 01 c6 45 ?? 00 c6 45 ?? 00 c6 45 ?? 00 c6 45 ?? 00 c6 45 ?? 00 c6 45 ?? 00}  //weight: 1, accuracy: Low
        $x_1_8 = {68 60 ea 00 00 e8 ?? ?? 00 00 8d 85 ?? ?? ff ff 50 68 02 02 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_9 = {eb 0a c7 85 ?? ?? ff ff ?? ?? 00 10 68 20 bf 02 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_Win32_Coroxy_ZA_2147843877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coroxy.ZA!MTB"
        threat_id = "2147843877"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 1a 03 1d ?? ?? ?? ?? 2b d8 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 89 18 e8 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 03 1d ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 03 1d ?? ?? ?? ?? 2b d8 e8 ?? ?? ?? ?? 03 d8 a1 ?? ?? ?? ?? 31 18 83 05 ?? ?? ?? ?? 04 83 05 ?? ?? ?? ?? 04 a1 ?? ?? ?? ?? 3b 05 ?? ?? ?? ?? 0f 82}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Coroxy_CA_2147900393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coroxy.CA!MTB"
        threat_id = "2147900393"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 8b 55 10 88 02 8a 07 30 02 ff 45 10 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Coroxy_CCHU_2147904692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coroxy.CCHU!MTB"
        threat_id = "2147904692"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 cc 03 55 ac 03 55 e8 2b d0 8b 45 d8 31 10 83 45 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Coroxy_FT_2147910134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Coroxy.FT!MTB"
        threat_id = "2147910134"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Coroxy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 00 89 45 ?? 8b 45 ?? 83 c0 ?? 89 45 ?? 33 c0 89 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 83 e8 ?? 89 45 ?? c7 45 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? 33 c0 89 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

