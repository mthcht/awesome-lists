rule Trojan_Win32_Shelm_RA_2147838872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.RA!MTB"
        threat_id = "2147838872"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 b0 18 40 00 10 59 40 3d dc 05 00 00 ?? f1}  //weight: 1, accuracy: Low
        $x_1_2 = "study\\shellcode_dll\\Release\\shellcode_dll.pdb" ascii //weight: 1
        $x_1_3 = "inject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_RB_2147844084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.RB!MTB"
        threat_id = "2147844084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {53 53 6a 03 53 66 ab 6a 03 53 68 ?? ?? ?? 00 c7 45 ec ?? ?? ?? 00 aa c7 45 f0 ?? ?? ?? 00 c7 45 f4 ?? ?? ?? 00 c7 45 f8 ?? ?? ?? 00 ff 15}  //weight: 5, accuracy: Low
        $x_1_2 = "fucking Wrong2" ascii //weight: 1
        $x_1_3 = "Reverse Shell Error" ascii //weight: 1
        $x_1_4 = "Usage : %s IP Port FileName <SaveName> /Upload | / Download" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_RK_2147850572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.RK!MTB"
        threat_id = "2147850572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6a 00 6a 02 c7 44 24 20 3c 88 01 10 c7 44 24 24 48 88 01 10 c7 44 24 28 54 88 01 10 c7 44 24 2c 60 88 01 10 c7 44 24 30 6c 88 01 10 c7 44 24 34 78 88 01 10 c7 44 24 38 88 88 01 10 c7 44 24 3c 94 88 01 10 c7 44 24 40 94 88 01 10 c7 44 24 44 a4 88 01 10 c7 44 24 48 b0 88 01 10 ff d7}  //weight: 5, accuracy: High
        $x_1_2 = "QQPCLeakScan.exe" ascii //weight: 1
        $x_1_3 = "Release\\shellcode" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_B_2147851499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.B!MTB"
        threat_id = "2147851499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {38 1e 8d 76 01 0f b6 c8 0f b6 d2 0f 44 d1 fe c0 3c 40 72 ?? 8b 45 fc 32 db 8a 4d f9 be ?? ?? ?? ?? 89 55 f0 8a 78 ff 0f}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 4d f4 8a c1 8b 75 ?? 89 55 f8 8b 55 f0 c0 e8 04 c0 e2 02 24 03 0a c2 8b 55 ?? 88 04 17 80 3e 3d 74}  //weight: 2, accuracy: Low
        $x_2_3 = "baes64 = %s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_C_2147852193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.C!MTB"
        threat_id = "2147852193"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 4d fc 3b 4d 0c 73 ?? 0f b6 55 10 8b 45 08 03 45 fc 0f b6 08 33 ca 8b 55 08 03 55 fc 88 0a eb}  //weight: 2, accuracy: Low
        $x_2_2 = "PQROXVOPRPOS" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_GMH_2147889034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.GMH!MTB"
        threat_id = "2147889034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 56 57 8b 3d ?? ?? ?? ?? 6a 00 6a 02 c7 85 80 fe ff ff ?? ?? ?? ?? c7 85 84 fe ff ff ?? ?? ?? ?? c7 85 88 fe ff ff ?? ?? ?? ?? c7 85 8c fe ff ff ?? ?? ?? ?? c7 85 ?? fe ff ff ?? ?? ?? ?? c7 85 94 fe ff ff ?? ?? ?? ?? c7 85 98 fe ff ff}  //weight: 10, accuracy: Low
        $x_1_2 = {4e 56 49 00 c7 85 ?? ?? ?? ?? 44 49 41 20 c7 85 ?? ?? ?? ?? 43 6f 72 00}  //weight: 1, accuracy: Low
        $x_1_3 = "QQPCLeakScan.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_D_2147892442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.D!MTB"
        threat_id = "2147892442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 88 08 21 40 00 80 f1 56 88 8c 05 ?? ?? ff ff 40 3d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_GMQ_2147892618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.GMQ!MTB"
        threat_id = "2147892618"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 45 10 2b 45 f4 c7 44 24 ?? ?? ?? ?? ?? 89 44 24 08 8b 45 f0 89 44 24 04 8b 45 08 89 04 24 e8 ?? ?? ?? ?? 83 ec 10 89 45 ec 8b 45 ec 01 45 f0 8b 45 ec 01 45 f4 83 7d ec ff ?? ?? c7 44 24 ?? 6e 50 40 00 8b 45 08 89 04 24}  //weight: 10, accuracy: Low
        $x_1_2 = "dz3.ddns.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_GMS_2147893128_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.GMS!MTB"
        threat_id = "2147893128"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 54 24 04 8d 4a 01 0f be c0 89 44 24 04 c1 f8 02 89 c7 83 e7 0f 89 f8 08 02 8b 44 24 04 c1 e0 06 88 42 01 e9 ?? ?? ?? ?? 8b 54 24 04 c7 45 ?? ?? ?? ?? ?? 0f b6 02 88 45 04 89 d0 29 f0 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_E_2147894374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.E!MTB"
        threat_id = "2147894374"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 34 18 59 40 8b 8d ?? ?? ff ff 3b c1}  //weight: 2, accuracy: Low
        $x_2_2 = {99 8d 7f 01 b9 ?? ?? ?? ?? f7 f9 8a 47 ?? 8b 8d ?? ?? ?? ?? fe c2 32 c2 34 ?? 88 04 0e 46 81 fe}  //weight: 2, accuracy: Low
        $x_2_3 = {99 8d 76 01 b9 ?? ?? ?? ?? f7 f9 8a 44 33 ?? 32 44 24 ?? fe c2 32 c2 88 46 ff 83 ef}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Shelm_F_2147894744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.F!MTB"
        threat_id = "2147894744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 10 2b 45 f4 c7 44 24 0c 00 00 00 00 89 44 24 08 8b 45 f0 89 44 24 04 8b 45 08 89 04 24 a1 ?? ?? ?? ?? ff d0 83 ec 10 89 45 ec 8b 45 ec 01 45 f0 8b 45 ec 01 45 f4 83 7d ec ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_G_2147899600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.G!MTB"
        threat_id = "2147899600"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "-nop -w hidden -e" ascii //weight: 2
        $x_2_2 = "ACQAZQBuAHYAOgB3AGkAbgBkAGkAcgArACcAXABzAHkAcwB3AG8AdwA2ADQAXABXAGkAbgBkAG8AdwBz" ascii //weight: 2
        $x_2_3 = "AFAAbwB3AGUAcgBTAGgAZQBsAGwAXAB2ADEALgAwAFwAcABvAHcAZQByAHMAaABlAGwAbAAuAGUAeABlAC" ascii //weight: 2
        $x_2_4 = "AE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEQAaQBhAGcAbgBv" ascii //weight: 2
        $x_2_5 = "AHMAdABpAGMAcwAuAFAAcgBvAGMAZQBzAHMAUwB0AGEAcgB0AEkAbgBmAG8A" ascii //weight: 2
        $x_2_6 = "ABbAFMAeQBzAHQAZQBtAC4AQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnAC" ascii //weight: 2
        $x_2_7 = "gAoAFsAcwBjAHIAaQBwAHQAYgBsAG8AYwBrAF0AOgA6AGMAcgBlAGEAdABlACgAKABOAGUAdwAtAE8AYg" ascii //weight: 2
        $x_2_8 = "BqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAGUAcgAoAE4AZQB3" ascii //weight: 2
        $x_2_9 = "AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEc" ascii //weight: 2
        $x_2_10 = "AegBpAHAAUwB0AHIAZQBhAG0AKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAEkATw" ascii //weight: 2
        $x_2_11 = "AuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtAC" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_M_2147906137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.M!MTB"
        threat_id = "2147906137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 c8 88 84 3d ?? ?? ?? ?? 0f b6 84 35 ?? ?? ?? ?? 03 c8 0f b6 c1 8b 8d d8 ?? ?? ?? 0f b6 84 05 ?? ?? ?? ?? 32 44 13 ?? 88 04 0a 42 81 fa}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_RS_2147910294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.RS!MTB"
        threat_id = "2147910294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 78 62 76 57 71 62 53 74 28 29 0a 77 58 4e 69 77 57 44 53 56 28 29 0a 4a 64 4f 64 61 6b 44 6d 69 28 29 0a 6d 47 43 79 4f 72 59 71 70 28 29}  //weight: 1, accuracy: High
        $x_1_2 = "( RunWait < FileDelete )" wide //weight: 1
        $x_1_3 = "( StrLen < Random )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Shelm_RR_2147913106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelm.RR!MTB"
        threat_id = "2147913106"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 8c 35 d4 fd ff ff 0f b6 c8 88 84 1d d4 fd ff ff 0f b6 84 35 d4 fd ff ff 03 c8 0f b6 c1 8b 8d e8 fe ff ff 0f b6 84 05 d4 fd ff ff 32 44 3a 08 88 04 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

