rule Trojan_Win32_RiseProStealer_PA_2147896832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.PA!MTB"
        threat_id = "2147896832"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 44 0d ?? 50 e8 [0-4] 88 44 0d ?? 41 83 f9 ?? 72 ?? 8d 45 ?? 50 56 ff ?? 5f a3 [0-4] 5e 8b e5 5d c3 [0-16] 55 8b ec 8a 45 08 34 33 5d c2 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_YAA_2147896861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.YAA!MTB"
        threat_id = "2147896861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f be c9 8d 52 01 33 ce 69 f1 93 01 00 01 8a 4a ff 84 c9}  //weight: 3, accuracy: High
        $x_2_2 = {8b ca 83 e1 0f b8 1d 8c 7c ee 83 f9 0f ba 40 bf fe f6 0f 43 cf c1 e1 02 e8 ?? ?? ?? ?? 8b 55 f0 24 0f 8d 4a 1d 32 c1 32 c3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_PB_2147896931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.PB!MTB"
        threat_id = "2147896931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 17 8b c3 8b d8 8b f6 33 f6 33 f6 8b de 33 f6 8b c3 33 f6 80 07 ?? 8b f6 8b db 8b d8 33 f0 33 db 33 f3 8b f3 33 de 33 c6 80 2f ?? 8b de 8b c0 8b d8 33 db 33 f3 8b c0 8b c6 33 f0 33 f3 f6 2f 47 e2 ab}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_PC_2147896951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.PC!MTB"
        threat_id = "2147896951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ca 23 ce b8 [0-4] 3b ce ba [0-4] 0f 43 ce c1 e1 02 e8 [0-4] 8b 55 fc 24 0f 8d 4a ?? 32 c1 32 c3 88 44 15 ?? 42 89 55 fc 83 fa ?? 72 ?? 0f 57 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_ARA_2147897510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.ARA!MTB"
        threat_id = "2147897510"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {69 4c 9d 00 91 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 91 e9 d1 5b 89 4c 24 28 85 d2 75 1c f6 c3 01 74 17 8d 47 fd 3b d8 7e 10}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_DA_2147897565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.DA!MTB"
        threat_id = "2147897565"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 0c b3 95 e9 d1 5b 46 69 ff 95 e9 d1 5b 8b c1 c1 e8 18 33 c1 69 c8 95 e9 d1 5b 33 f9 3b f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_A_2147898301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.A!MTB"
        threat_id = "2147898301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c2 d3 e8 8b 4d ?? 8d 34 13 81 c3 ?? ?? ?? ?? 03 45 ?? 33 c6 33 c8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_YAB_2147899045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.YAB!MTB"
        threat_id = "2147899045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 5a 37 59 8b 45 d8 8b 4d dc c5 fe 6f 85 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 89 8d ?? ?? ?? ?? c5 fd ef 85 ?? ?? ?? ?? 50 c5 fd 7f 85 ?? ?? ?? ?? 57 c5 f8 77 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_AD_2147899885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.AD!MTB"
        threat_id = "2147899885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 01 8b 0c 24 83 c4 04 52 50}  //weight: 1, accuracy: High
        $x_1_2 = {01 d0 01 18 58 5a 55 52}  //weight: 1, accuracy: High
        $x_1_3 = {89 14 24 ba 83 41 d9 71 c1 e2 03 c1 ea 02 81 c2 fb 7c 4d dc 29 d1 5a}  //weight: 1, accuracy: High
        $x_1_4 = "Ay3Info.exe" ascii //weight: 1
        $x_1_5 = "%userappdata%\\RestartApp.exe" ascii //weight: 1
        $x_1_6 = "\\.\\Global\\oreans32" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_AD_2147899885_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.AD!MTB"
        threat_id = "2147899885"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "33648d89-b00c-47ef-9100-1c5557768c3a" ascii //weight: 1
        $x_1_2 = "PolymodXT" ascii //weight: 1
        $x_1_3 = "nitOKlp6an4rTirqmku63itOKuqaS7reK04ry6va3itOK8ur2t" ascii //weight: 1
        $x_1_4 = "failed readpacket" ascii //weight: 1
        $x_1_5 = "faield sendpacket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_AB_2147900206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.AB!MTB"
        threat_id = "2147900206"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fb 9e b5 50 16 bf 4c 42 b4 46 fc 21 0b 8e 6e b8}  //weight: 1, accuracy: High
        $x_1_2 = "Get my money" ascii //weight: 1
        $x_1_3 = "PolymodXT" ascii //weight: 1
        $x_1_4 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36" ascii //weight: 1
        $x_1_5 = "failed readpacket" ascii //weight: 1
        $x_1_6 = "faield sendpacket" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_AC_2147900289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.AC!MTB"
        threat_id = "2147900289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f be c9 8d 52 01 33 ce 69 f1 93 01 00 01 8a 4a ff 84 c9}  //weight: 2, accuracy: High
        $x_2_2 = "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0" ascii //weight: 2
        $x_2_3 = "RiseProSUPPORT" ascii //weight: 2
        $x_1_4 = "eyAidHlwIjogIkpXVCIsICJhbGciOiAiRWREU0EiIH0." ascii //weight: 1
        $x_1_5 = "lazeryoungthug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_RiseProStealer_GSA_2147900567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.GSA!MTB"
        threat_id = "2147900567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 d1 e8 33 db 8a 5c 85 c8 8a 9b ?? ?? ?? ?? 30 5c 85 cc 33 db 8a 5c 85 c9 8a 9b ?? ?? ?? ?? 30 5c 85 cd 33 db 8a 5c 85 ca 8a 9b 14 b7 63 01 30 5c 85 ce 33 db 8a 5c 85 cb 8a 9b 14 b7 63 01 30 5c 85 cf 40 8b d9 4b 2b d8 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_B_2147903169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.B!MTB"
        threat_id = "2147903169"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 f3 31 03 5b 83 ec 17 00 53 55 68 ?? ?? ?? ?? 5d 81 cd ?? ?? ?? ?? 81 c5 ?? ?? ?? ?? 55 5b 5d}  //weight: 2, accuracy: Low
        $x_2_2 = {5e 01 f2 01 1a 5a 68}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_RHA_2147904547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.RHA!MTB"
        threat_id = "2147904547"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 01 0e 22 00 ac 10 00 00 3e 04 00 00 00 00 00 00 c0 15 00 00 10 00 00 00 c0 10}  //weight: 2, accuracy: High
        $x_2_2 = {2e 72 73 72 63 00 00 00 f8 0e 01 00 00 b0 14 00 f8 0e 01 00 00 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 00 00 00 00 00 00 00 00 00 80 01 00 00 c0 15 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 e0}  //weight: 2, accuracy: Low
        $x_2_3 = {e8 18 00 00 00 eb 03}  //weight: 2, accuracy: High
        $x_1_4 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 41 00 75 00 33 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 41 00 79 00 33 00 49 00 6e 00 66 00 6f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_RHB_2147905641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.RHB!MTB"
        threat_id = "2147905641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 01 0e 22 00 b6 10 00 00 ?? 03}  //weight: 2, accuracy: Low
        $x_2_2 = {40 00 00 e0 2e 72 73 72 63 00 00 00 70 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 74 61 67 67 61 6e 74}  //weight: 2, accuracy: Low
        $x_2_3 = {54 b0 13 00 68 00 00 00 00 80 13 00 70 2e}  //weight: 2, accuracy: High
        $x_2_4 = {e9 00 20 00 00 00 0a 00 eb 08}  //weight: 2, accuracy: Low
        $x_2_5 = "yoursite@yoursite.com." ascii //weight: 2
        $x_1_6 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 2e 00 4e 00 45 00 54 00 20 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_7 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 ?? ?? 4d 00 53 00 42 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_RHC_2147906245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.RHC!MTB"
        threat_id = "2147906245"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 20 20 00 20 20 20 20 00 50 13 00 00 10 00 00 00 e8 08 00 00 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 40 00 00 e0 2e 72 73 72 63}  //weight: 2, accuracy: Low
        $x_2_2 = {56 50 53 e8 01 00 00 00 ?? 58 89 c3}  //weight: 2, accuracy: Low
        $x_2_3 = "Sorry, this application cannot run under a Virtual Machine" ascii //weight: 2
        $x_1_4 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 48 00 65 00 69 00 64 00 69 00 53 00 51 00 4c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 ?? ?? 68 00 65 00 69 00 64 00 69 00 73 00 71 00 6c 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_2_6 = {50 45 00 00 4c 01 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0e 22 00 9e 10 00 00 6c 03 ?? ?? ?? ?? ?? ?? ?? 3a 00 00 10 00 00 00 b0 10}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_RHD_2147906811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.RHD!MTB"
        threat_id = "2147906811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {40 00 00 e0 2e 72 73 72 63 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 74 61 67 67 61 6e 74}  //weight: 2, accuracy: Low
        $x_2_2 = {e9 00 20 00 00 00 0a 00 eb 08}  //weight: 2, accuracy: Low
        $x_2_3 = "yoursite@yoursite.com." ascii //weight: 2
        $x_1_4 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 2e 00 4e 00 45 00 54 00 20 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_5 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 ?? ?? 4d 00 53 00 42 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_2_6 = {50 45 00 00 4c 01 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0e 22 00 ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 00 00 00 ?? 10 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_RHE_2147907079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.RHE!MTB"
        threat_id = "2147907079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 75 e0 e8 ?? ?? 00 00 cc e8 ?? ?? 00 00 e9 ?? ?? ff ff}  //weight: 2, accuracy: Low
        $x_2_2 = {53 74 65 61 6c 65 72 43 6c 69 65 6e 74 2e 65 78 65 00 53 74 61 72 74}  //weight: 2, accuracy: High
        $x_2_3 = {52 69 73 65 50 72 6f ?? ?? 54 65 6c 65 67 72 61 6d 3a 20 68 74 74 70 73 3a 2f 2f 74 2e 6d 65 2f 52 69 73 65 50 72 6f 53 55 50 50 4f 52 54}  //weight: 2, accuracy: Low
        $x_2_4 = {50 45 00 00 4c 01 05 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0e 22 00 ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 10 00 00 00 ?? 10 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_RHG_2147910128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.RHG!MTB"
        threat_id = "2147910128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 76 6d 70 c2 b3 c2 a4 55 fd 1c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 76 6d 70}  //weight: 2, accuracy: Low
        $x_2_2 = {e8 a8 7e d7 ff b3 b0 84 77 50 f9 4e f0 21 62 64 ea}  //weight: 2, accuracy: High
        $x_2_3 = {50 45 00 00 4c 01 0a ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0e 27 00 34 11 00 00 30 08 00 00 00 00 00 f3 11 92}  //weight: 2, accuracy: Low
        $x_2_4 = {53 74 61 72 74 00 53 74 65 61 6c 65 72 43 6c 69 65 6e 74 2e 65 78 65}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_RHH_2147910354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.RHH!MTB"
        threat_id = "2147910354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2e 76 6d 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 76 6d 70}  //weight: 2, accuracy: Low
        $x_2_2 = {50 45 00 00 4c 01 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0e 27 00 34 11 00 00 34 08}  //weight: 2, accuracy: Low
        $x_2_3 = {53 74 61 72 74 00 53 74 65 61 6c 65 72 43 6c 69 65 6e 74 2e 65 78 65}  //weight: 2, accuracy: High
        $x_1_4 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 47 00 6c 00 61 00 72 00 79 00 20 00 55 00 74 00 69 00 6c 00 69 00 74 00 69 00 65 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_C_2147912976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.C!MTB"
        threat_id = "2147912976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 8d 18 ff ff ff 8b c1 8b bd 14 ff ff ff 2b c7 8b 95 3c ff ff ff 8b b5 34 ff ff ff 42 c1 f8 ?? 83 c6 ?? 69 c0 ?? ?? ?? ?? 89 95 3c ff ff ff 89 b5 34 ff ff ff 3b d0}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 8d 18 ff ff ff 8b c1 8b bd 14 ff ff ff 2b c7 c1 f8 ?? 69 c0 ab aa aa aa c7 85 3c ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_RHF_2147913361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.RHF!MTB"
        threat_id = "2147913361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {40 00 00 e0 2e 72 73 72 63 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 74 61 67 67 61 6e 74}  //weight: 2, accuracy: Low
        $x_2_2 = {e9 00 20 00 00 00 0a 00 eb 08}  //weight: 2, accuracy: Low
        $x_2_3 = {50 45 00 00 4c 01 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0e 22 00 ?? 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5c 00 00 10 00 00 00 ?? 10 00}  //weight: 2, accuracy: Low
        $x_1_4 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 41 00 75 00 33 00}  //weight: 1, accuracy: Low
        $x_1_5 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 ?? ?? ?? ?? 41 00 79 00 33 00 49 00 6e 00 66 00 6f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RiseProStealer_ADG_2147918115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RiseProStealer.ADG!MTB"
        threat_id = "2147918115"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RiseProStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 a1 30 00 00 00 8b 48 0c 89 8d 74 fd ff ff 8b 95 74 fd ff ff 8b 42 0c 89 85 70 fd ff ff 8b 8d 70 fd ff ff 89 8d d8 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

