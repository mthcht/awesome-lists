rule Trojan_Win32_Fareit_K_2147730468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.K!MTB"
        threat_id = "2147730468"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 8b 45 08 [0-4] 8a 10 80 f2 ?? [0-4] 88 10 5d c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 06 03 c3 50 ff 15 ?? ?? ?? ?? [0-4] ff 06 81 3e ?? ?? ?? ?? 75 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_R_2147731003_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.R!MTB"
        threat_id = "2147731003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 8b f0 8b ca 85 c9 72 10 41 33 d2 8d 3c 32 8a 07 34 e5 88 07 42 49 75 f3 5f 5e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_R_2147731003_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.R!MTB"
        threat_id = "2147731003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 ff 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90}  //weight: 1, accuracy: High
        $x_1_2 = {83 fb 00 7f [0-13] 83 c4 78 [0-21] ff [0-2] 50 00 8b 14 1f [0-15] e8 [0-21] 89 14 18 [0-15] 83 fb 00 7f}  //weight: 1, accuracy: Low
        $x_1_3 = {39 18 90 90 90 90 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_R_2147731003_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.R!MTB"
        threat_id = "2147731003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Sanmarcos7" ascii //weight: 1
        $x_1_2 = "Fleishacker5" ascii //weight: 1
        $x_1_3 = "Overpersuade6" ascii //weight: 1
        $x_1_4 = "Hammerwise5" ascii //weight: 1
        $x_1_5 = "Kadukali2" wide //weight: 1
        $x_1_6 = "BeBiRd" wide //weight: 1
        $x_1_7 = "KIlatos.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_R_2147731003_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.R!MTB"
        threat_id = "2147731003"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hraTTB.exe" wide //weight: 1
        $x_1_2 = "preparstabile" ascii //weight: 1
        $x_1_3 = "preparBLUEGOWN" ascii //weight: 1
        $x_1_4 = "preparSLANGIER" ascii //weight: 1
        $x_1_5 = "preparVOLOS" ascii //weight: 1
        $x_1_6 = "preparubiquit9" ascii //weight: 1
        $x_1_7 = "preparTurutap4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_2147740161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit!MTB"
        threat_id = "2147740161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 6b df ff 34 1f 0f fd c8 5a 31 f2 09 14 18 0f 67 f9 85 db 75 03 00 83 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SF_2147742418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SF!MTB"
        threat_id = "2147742418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 10 b1 f8 40 [0-6] 81 c1 31 90 48 00 [0-16] f7 c1 ef 37 b6 4a [0-21] 39 cb 75}  //weight: 1, accuracy: Low
        $x_1_2 = {66 3d 3a c6 39 da 83 eb 03 [0-6] 83 eb 01 [0-6] ff 34 1f [0-16] 8f 04 18 [0-6] 38 ff 31 34 18 [0-37] 3d e2 89 b8 4a 83 fb 00 7f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VP_2147743793_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VP!MTB"
        threat_id = "2147743793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? c7 45 08 ?? ?? ?? ?? 81 45 08 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 03 45 08 6a ?? a3 ?? ?? ?? ?? 6a ?? c1 e8 ?? 30 04 3e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VP_2147743793_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VP!MTB"
        threat_id = "2147743793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 74 1d ff 8b c6 83 c0 ?? 83 e8 ?? 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 04 24 e8 ?? ?? ?? ?? 8d 44 18 ff 50 8d 46 0e b9 ?? ?? ?? ?? 99 f7 f9 83 c2 ?? 58 88 10 43 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VP_2147743793_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VP!MTB"
        threat_id = "2147743793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d fc 8b 45 08 8b 00 83 45 fc ?? 8d 14 08 8a 4a 03 8a c1 8a d9 80 e1 ?? 24 ?? c0 e1 ?? 0a 0a c0 e0 ?? 0a 42 01 c0 e3 ?? 0a 5a 02 88 0c 3e 8b 4d fc 46 88 04 3e 8b 45 0c 46 88 1c 3e 46 3b 08 72}  //weight: 1, accuracy: Low
        $x_1_2 = {50 56 56 ff 15 ?? ?? ?? ?? e8 ?? ?? ?? ?? 30 04 1f 4f 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VP_2147743793_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VP!MTB"
        threat_id = "2147743793"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 fc 0f b6 5c 38 ff 0f b6 c3 83 e0 ?? 85 c0 75 ?? 8d 45 ec 0f b6 d3 2b 55 f4 e8 ?? ?? ?? ?? 8b 55 ec 8d 45 f8 e8 ?? ?? ?? ?? eb ?? 8d 45 e8 0f b6 d3 03 55 f4 e8 ?? ?? ?? ?? 8b 55 e8 8d 45 f8 e8 ?? ?? ?? ?? 47 4e 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 f4 8b 45 f8 e8 ?? ?? ?? ?? 8b d8 4b 83 fb ?? 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 8b 45 f0 8b 00 8d 04 b0 8b 55 f4 e8 ?? ?? ?? ?? eb ?? 8b 45 f0 8b 00 8d 04 b0 50 8b cb ba ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 8b 45 f8 85 c0 74 ?? 83 e8 ?? 8b 00 8d 0c 18 8d 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 46 83 7d f4 ?? 75}  //weight: 1, accuracy: Low
        $x_2_3 = {8d 45 f0 50 8b c7 48 8b d0 03 d2 42 b9 ?? ?? ?? ?? 8b 45 fc e8 ?? ?? ?? ?? 8b 4d f0 8d 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 8b d0 8d 45 f8 e8 ?? ?? ?? ?? 8b 55 f8 8b c6 e8 ?? ?? ?? ?? 47 4b 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_V_2147743811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.V!MTB"
        threat_id = "2147743811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 03 d0 73 ?? ?? ?? ?? ?? ?? 80 32 98 40 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_V_2147743811_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.V!MTB"
        threat_id = "2147743811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 4c 14 10 f7 ef 03 d7 80 f1 ?? c1 fa ?? 8b c2 c1 e8 ?? 03 d0 88 0c 32 8a 04 2e 3c ?? 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_V_2147743811_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.V!MTB"
        threat_id = "2147743811"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {30 04 3e 46 05 00 e8}  //weight: 2, accuracy: Low
        $x_1_2 = {55 8b ec a1 ?? ?? ?? ?? 69 c0 ?? ?? ?? ?? 83 ec ?? 6a ?? 6a ?? 05 ?? ?? ?? ?? 6a ?? a3 ?? ?? ?? ?? ff 15 [0-16] 8d 4d a0 51 6a ?? 6a ?? e8 ?? ?? ?? ?? 0f b7 05 ?? ?? ?? ?? 25 ?? ?? ?? ?? 8b e5 5d c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VM_2147744070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VM!MTB"
        threat_id = "2147744070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 10 0f b6 14 3a 33 c2 3d ?? ?? ?? ?? 76}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 55 10 88 04 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VM_2147744070_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VM!MTB"
        threat_id = "2147744070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 06 03 c3 73 ?? e8 ?? ?? ?? ?? 50 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? ?? ff 06 81 3e ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 45 08 5a 30 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VM_2147744070_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VM!MTB"
        threat_id = "2147744070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e8 c3 29 f9 ff 8a 84 85 e8 fb ff ff 30 06}  //weight: 1, accuracy: High
        $x_1_2 = {8a 84 9d e8 fb ff ff 88 45 ?? 89 c0 89 f6 89 d2 87 ff 8b 84 bd e8 fb ff ff 89 84 9d e8 fb ff ff 90 89 db 90 33 c0 8a 45 ?? 89 84 bd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fareit_VM_2147744070_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VM!MTB"
        threat_id = "2147744070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c1 33 d2 52 50 8b 03 99 03 04 24 13 54 24 04 83 c4 ?? c6 00 ?? ff 03 81 3b ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = "DNY9v2DwYl7cTUaK6i4ZShXnuOcDfnmpvT" ascii //weight: 1
        $x_1_3 = {68 68 17 47 00 e8 ?? ?? ?? ?? 4b 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_P_2147744137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.P!MTB"
        threat_id = "2147744137"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 8b 1c 0e [0-32] 66 09 1c 0f [0-48] 49 [0-37] 49 [0-128] 85 c9 0f}  //weight: 1, accuracy: Low
        $x_1_2 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_PA_2147744464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.PA!MTB"
        threat_id = "2147744464"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {5d c2 08 00 40 00 55 8b ec 90 [0-10] 8b c1 90 [0-10] 8a 90 ?? ?? ?? 00 32 55 0c 90 [0-10] 03 45 08 90 [0-10] 8b c8 90 [0-10] 8b c2 90 [0-10] 88 01 90}  //weight: 20, accuracy: Low
        $x_20_2 = {5d c2 08 00 40 00 55 8b ec 90 [0-10] 8a 91 ?? ?? ?? 00 32 55 0c 90 [0-10] 03 4d 08 90 [0-10] 8b c2 90 [0-10] 88 01 90}  //weight: 20, accuracy: Low
        $x_1_3 = {55 8b ec 83 c4 f8 89 55 f8 89 45 fc 90 [0-10] 8b ?? fc ff 75 f8 01 ?? 24 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_1_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_SM_2147744490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SM!MTB"
        threat_id = "2147744490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 46 04 8b 16 01 d8 01 da e8 76 1e 00 00 83 c6 08 4f 75 ec}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 f0 88 02 90 90 90 90 ff 45 ec ff 4d dc 0f 85 5a fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SM_2147744490_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SM!MTB"
        threat_id = "2147744490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {88 10 83 c1 ?? 73 09 00 8a 91 ?? ?? ?? ?? 80 f2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VA_2147745218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VA!MTB"
        threat_id = "2147745218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4c 24 04 30 01}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c 24 08 0f af c8 89 0c 24 c7 44 24 04 ?? ?? ?? ?? 81 44 24 04 ?? ?? ?? ?? 8b 44 24 04 01 04 24 8b 04 24 a3 ?? ?? ?? ?? c1 e8 ?? 25 ?? ?? ?? ?? 83 c4 ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VC_2147745515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VC!MTB"
        threat_id = "2147745515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 45 f8 83 c0 ?? 89 45 f8 8b 4d f8 3b 4d f4 73 ?? ff 15 ?? ?? ?? ?? 6a ?? ff 15 ?? ?? ?? ?? 8b 55 10 52 8b 45 f8 d1 e0 8b 4d fc 8d 14 81 52 e8 ?? ?? ?? ?? 83 c4 ?? eb}  //weight: 2, accuracy: Low
        $x_1_2 = {8b 4d dc c1 e1 ?? 03 4d e8 8b 55 dc 03 55 f0 33 ca 8b 45 dc c1 e8 ?? 03 45 ec 33 c8 8b 55 f4 2b d1 89 55 f4}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 45 f4 c1 e0 ?? 03 45 f8 8b 4d f4 03 4d f0 33 c1 8b 55 f4 c1 ea ?? 03 55 e0 33 c2 8b 4d dc 2b c8 89 4d dc 8b 55 e4 83 c2 ?? 8b 45 f0 2b c2 89 45 f0 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_VD_2147745532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VD!MTB"
        threat_id = "2147745532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d3 03 d0 80 32 ?? 40 3d ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VD_2147745532_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VD!MTB"
        threat_id = "2147745532"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 f7 f3 85 d2 [0-64] 8b d6 03 d1 [0-64] b0 [0-64] 30 02 [0-64] 41}  //weight: 1, accuracy: Low
        $x_1_2 = {33 d2 f7 f7 85 d2 [0-64] 8b c6 03 c1 [0-64] 30 18 [0-64] 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fareit_VL_2147748552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VL!MTB"
        threat_id = "2147748552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {51 59 8b 04 0f 66 3d ?? ?? e8 ?? ?? ?? ?? 52 5a 89 04 0f 66 81 f9 ?? ?? 66 83 e9 ?? 66 3d ?? ?? 81 f9 ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
        $x_1_2 = {31 f0 66 81 fa ?? ?? c3 04 00 66 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VL_2147748552_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VL!MTB"
        threat_id = "2147748552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 0f 66 81 f9 ?? ?? e8 ?? ?? ?? ?? 50 58 89 04 0f 81 fd ?? ?? ?? ?? 66 83 e9 ?? 81 fc ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75 03 00 80 fe}  //weight: 1, accuracy: Low
        $x_1_2 = {50 58 31 f0 66 81 fb ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VL_2147748552_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VL!MTB"
        threat_id = "2147748552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 04 0f 53 5b e8 ?? ?? ?? ?? 80 fd ?? 89 04 0f 66 3d ?? ?? 66 83 e9 ?? 66 3d ?? ?? 81 f9 ?? ?? ?? ?? 75 03 00 80 fc}  //weight: 1, accuracy: Low
        $x_1_2 = {31 f0 66 3d ?? ?? c3 04 00 66 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VL_2147748552_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VL!MTB"
        threat_id = "2147748552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {89 4c 24 04 c1 64 24 04 ?? 8b 44 24 0c 01 44 24 04 89 0c 24 c1 2c 24 ?? 8b 44 24 14 01 04 24 8b 44 24 10 03 c1 33 04 24 33 44 24 04 83 c4 ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 44 24 24 89 78 04 ?? ?? ?? 89 18}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VL_2147748552_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VL!MTB"
        threat_id = "2147748552"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 14 0f 66 f7 c3 ?? ?? 31 f2 f7 c7 ?? ?? ?? ?? 09 14 08 66 f7 c2 ?? ?? 85 c9 75 09 00 83 e9 ?? f7 c4}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 14 0f 66 f7 c2 ?? ?? 31 f2 66 f7 c2 ?? ?? 09 14 08 f6 c1 ?? 85 c9 75 09 00 83 e9 ?? f7 c4}  //weight: 2, accuracy: Low
        $x_2_3 = {8b 14 0f a8 ?? 31 f2 f6 c1 ?? 09 14 08 f6 c2 ?? 85 c9 75 06 00 83 e9 ?? f6 c7}  //weight: 2, accuracy: Low
        $x_2_4 = {8b 14 0f eb ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f2 81 fe ?? ?? ?? ?? 09 14 08 eb ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 c9 75 09 00 83 e9 ?? 81 fe}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fareit_VZ_2147749117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VZ!MTB"
        threat_id = "2147749117"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff 34 0f 80 fb ?? 58 80 f9 ?? e8 ?? ?? ?? ?? 80 fb ?? 89 04 0f 3c ?? 83 e9 ?? 80 f9 ?? 81 f9 ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
        $x_2_2 = {8b 04 0f 3c ?? e8 ?? ?? ?? ?? 80 fb ?? 89 04 0f 3c ?? 66 41 3c ?? 66 41 80 fb ?? 66 41 80 fb ?? 66 41 3c ?? 81 f9 ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
        $x_2_3 = {31 c0 80 f9 ?? 0b 04 0f 3c ?? e8 ?? ?? ?? ?? 80 fb ?? 6a ?? 3c ?? 8f 04 0f 80 fb ?? 09 04 0f 3c ?? 83 e9 ?? 80 fb ?? 81 f9 ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
        $x_1_4 = {31 f0 80 fb ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_SK_2147749842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SK!eml"
        threat_id = "2147749842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 0c 30 8a 09 90 80 f1 38 8d 1c 30 88 0b 40 4a 75 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SK_2147749842_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SK!eml"
        threat_id = "2147749842"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 8d 14 03 80 32 30 40 3d 09 5c 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_CZ_2147749953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.CZ!eml"
        threat_id = "2147749953"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 1c 10 8a 1b 80 f3 3e 8d 34 02 88 1e 42 49 75 ef}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "PULx9J99eP0jRV3p7OJHxVrvug7DNmV21" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "Uck9uNP06zOp84Xlr71D113" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "ZJSEpRxThKFmFqjDqJZ40y85L74211" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "r6ypTbjlHeYbZfBvy57" wide //weight: 1
        $x_1_3 = "QWABAKfy53" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "RKuuqILm1zA3JjWpAcca0hcDtpvSwh6M205" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Kawaii-Unicorn.exe" ascii //weight: 1
        $x_1_2 = "cmd /c rename" ascii //weight: 1
        $x_1_3 = "DllFunctionCall" ascii //weight: 1
        $x_1_4 = "I'm Unicorn" ascii //weight: 1
        $x_1_5 = "\\Unicorn" ascii //weight: 1
        $x_1_6 = "VB.Clipboard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "w34UEU0Iylueo0jCVD5Cc6Y51" wide //weight: 1
        $x_1_3 = "FaAdASg12jTEO7ieXfroTvKuO24" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "WILDNESSES" wide //weight: 1
        $x_1_3 = "missounding" wide //weight: 1
        $x_1_4 = "NONCONSOLING" wide //weight: 1
        $x_1_5 = "intertill" wide //weight: 1
        $x_1_6 = "TACHOMETRE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "fbSqoquZN2kHdpxenSuwlSdwWm2pCEqJp126" wide //weight: 1
        $x_1_3 = "mmqHtzuMHLtnxAgkOyecbODJFkqBB47" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "JIhwDHvBoHY3JOrnJ8KYLR201" wide //weight: 1
        $x_1_3 = "GhDlkLdMMlXmLn5yL2o1tLSOCXEDXV7nw5i2asvKkjd718161" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_10
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "N0hSj0VmQK0uFUOp82269ZrqWEEr4148" wide //weight: 1
        $x_1_3 = "EshO3XSZWnB0slrzS4vP0fCUN22zgsucCZsXDiD75" wide //weight: 1
        $x_1_4 = "zJocRkx78" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_11
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "VpJQVivqKqHorPeOlS4DcE19CzUQQiLiCTywq9S93" wide //weight: 1
        $x_1_3 = "Z7Cs8VP9jVsKlxJPCqgUFIdM5yKiuPK6215" wide //weight: 1
        $x_1_4 = "EHcZaHOvFcx210" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_12
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "VARMGALVANISERING" wide //weight: 1
        $x_1_3 = "kollaboratrs" wide //weight: 1
        $x_1_4 = "tilbagelagte" wide //weight: 1
        $x_1_5 = "VANISHINGLY" wide //weight: 1
        $x_1_6 = "Kolonimagter5" wide //weight: 1
        $x_1_7 = "Barberingerne" wide //weight: 1
        $x_1_8 = "Selvmordsforsgs3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_13
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "Z5zLsZeWKW8cithRjMzu4ON7xuK146" wide //weight: 1
        $x_1_3 = "s60MfRFb0UOcVueFwUAZGj1Z0Fc1q2rsX9b56" wide //weight: 1
        $x_1_4 = "cae3PdAJIZ9D39" wide //weight: 1
        $x_1_5 = "146\\s60M" wide //weight: 1
        $x_1_6 = "VueFwUAZGj1Z0Fc1q2rsX9b56" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_14
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "antiracketeeringdignifyingsoekoedominati" wide //weight: 1
        $x_1_3 = "TREKLANGLUDWIGROO" wide //weight: 1
        $x_1_4 = "Michaelmasraspitebillowunluckiest" wide //weight: 1
        $x_1_5 = "WfOMoDCNjd38zZvJ6ysfPRkl14" wide //weight: 1
        $x_1_6 = "Tilefishessupramolec" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_15
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "x8j805226" wide //weight: 1
        $x_1_3 = "kYsYVfEz36" wide //weight: 1
        $x_1_4 = "f2ku4zUj4iNLJAoRYu4PdxR148" wide //weight: 1
        $x_1_5 = "fQ65Z7T1AuFmNozZ3lG248ahxnL53" wide //weight: 1
        $x_1_6 = "BjHX5o9SQVl8QS1NYiwarqK221" wide //weight: 1
        $x_1_7 = "Nc8Rn9umj9e30" wide //weight: 1
        $x_1_8 = "lnVeFJ4py0GznW6ZmwQpilOwe0GwCYH2DvzgK1F30" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_VB_2147750074_16
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "inbigCarUPwMWO68" wide //weight: 1
        $x_1_3 = "ys01DH1Y4PyQhTwESnxu79" wide //weight: 1
        $x_1_4 = "KcoVY2AoFY4mCEFZOfD0eNIM6L189" wide //weight: 1
        $x_1_5 = "Tgvf233" wide //weight: 1
        $x_1_6 = "ku0dcvhDqz2BYQGxTgb1GoEkUv50cU222" wide //weight: 1
        $x_1_7 = "u1ZNSXWMC33sKoa8XcwQKn38" wide //weight: 1
        $x_1_8 = "WpHGgiz152" wide //weight: 1
        $x_1_9 = "Bcw4Y6XyvNc83zUeoSg146" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_17
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mjNKnZQA6iMA1360TmE7qpXfdCI125KOccZ228" wide //weight: 1
        $x_1_2 = "GmKrakOCLnrF65bYPd9ivA8i76" wide //weight: 1
        $x_1_3 = "RIGykLlrlSInysHyWNsdlHBq7sp65RtfLHyvO73" wide //weight: 1
        $x_1_4 = "N6C911psm149" wide //weight: 1
        $x_1_5 = "Kx8hfCkFs9zIfhXtv8IxvLbdou1U6nBGnYOh7nWa55" wide //weight: 1
        $x_1_6 = "RvfRLmk2gUH7DeIrS6y104" wide //weight: 1
        $x_1_7 = "WiwaAYT167" wide //weight: 1
        $x_1_8 = "ZhGCAOoPff6RL13pcKZuurqWg411" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_18
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_2_2 = "koxvzuiczqeidssoinjzupjkuhiiqur" ascii //weight: 2
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide //weight: 1
        $x_1_4 = "\\Microsoft.NET\\Framework\\v2.0.50727\\RegAsm.ExE" wide //weight: 1
        $x_1_5 = "\\Microsoft.NET\\Framework\\v4.0.30319\\RegSvcs.exe" wide //weight: 1
        $x_1_6 = "SCHTASKS.exe /CREATE /SC ONLOGON /RL HIGHEST /TR" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_19
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "RygHUbiY6GHjMWmj4jKQyTci4ZfjK10" wide //weight: 1
        $x_1_3 = "LzWOUujvHMG2pXr6yNpXSluKymtYG189" wide //weight: 1
        $x_1_4 = "tTqqIt1PkrU8Mh6DfdwV1cU1576PSpoDtJmbO195" wide //weight: 1
        $x_1_5 = "ZT1TucXONmALAi13d6HSusuaO111" wide //weight: 1
        $x_1_6 = "phzkSG4WV98FjGO9yZXDEsCNZ9y9Ck238" wide //weight: 1
        $x_1_7 = "JpJToDFrVQWfUNvsPGcCNIC6xcaALF59" wide //weight: 1
        $x_1_8 = "o5lWNe3Erk1gmuZhDQzPu3U8MPWjIRzoM92" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_VB_2147750074_20
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "TrURQCu02nsFyy2MVzQ3lVaa14thOtbH9VGP8bBm177" wide //weight: 1
        $x_1_3 = "rotmuaFv5wp3tvcJvqD5EF6jmJHqAtqGJA182" wide //weight: 1
        $x_1_4 = "IRKS18zEfaGVIYP5IPWShEanqu9gtnwdK252" wide //weight: 1
        $x_1_5 = "Ek5EUXgeau3YLs9Wmr8oXZHpbPVFKk4zhbkyjo32" wide //weight: 1
        $x_1_6 = "nFoC41dDQrS5mCDmf2ed3LQ87kgVSTcurO126" wide //weight: 1
        $x_1_7 = "WrTEcyfPi120" wide //weight: 1
        $x_1_8 = "ejDqt1zNaMZDxgYC6fhc8cyhnczmZ7RGJVtQs11" wide //weight: 1
        $x_1_9 = "V3rS1Ecei0Pw30b64" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Fareit_VB_2147750074_21
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VB!MTB"
        threat_id = "2147750074"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSVBVM60.DLL" ascii //weight: 1
        $x_1_2 = "Xnp9qffyECmNnejKmWqZdXOI168" wide //weight: 1
        $x_1_3 = "qpPad7HNTz3N0ghzA4ruQs3A2H5sDthyF228" wide //weight: 1
        $x_1_4 = "IhzWuA1MLJX6A8qUNOJkQ1100" wide //weight: 1
        $x_1_5 = "ElssDUhwZxHIiceMq5WO8MDGRMkHNkVrdlbV237" wide //weight: 1
        $x_1_6 = "HrcsPa2c2pPrIpZHSpPX8S1UUPwxTxCNJoeHZ0yx2" wide //weight: 1
        $x_1_7 = "hRpCldSMpO983PoIDnaoOtbDvsiq1uLxosNU8Zi193" wide //weight: 1
        $x_1_8 = "vV3q9RRkEYNXMSyu3IjHd7F7HzP203" wide //weight: 1
        $x_1_9 = "A839Z1oeASc3IZz3yab64Q151" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Fareit_DEL_2147750226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.DEL!MTB"
        threat_id = "2147750226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "anmN82sLjR" ascii //weight: 1
        $x_1_2 = "IC19u15J14dn7R4J3P5QavJ9bU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_DEL_2147750226_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.DEL!MTB"
        threat_id = "2147750226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "s2YXEKFA0Kk" ascii //weight: 1
        $x_1_2 = "5VSK0c4PPhZAYaTtN" ascii //weight: 1
        $x_2_3 = {89 1e a1 60 bc 47 00 03 06 8a 00 34 ?? 8b 15 60 bc 47 00 03 16 88 02 ?? ?? 43 81 fb ?? ?? ?? ?? 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_DEL_2147750226_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.DEL!MTB"
        threat_id = "2147750226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YlcF3nkOJOKQ88SJsUazBPvEmrRIR0D5tWBdkT" ascii //weight: 1
        $x_1_2 = "Ntc1bclaPeAFqnX9cuH" ascii //weight: 1
        $x_1_3 = "oC2j2EYL5xWaQzvj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_DEL_2147750226_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.DEL!MTB"
        threat_id = "2147750226"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8nTbclBLbUziX1BXckt3Rqa7WSM2d9KJnVLcHUD" ascii //weight: 1
        $x_1_2 = "CfB99aeze4Ow" ascii //weight: 1
        $x_1_3 = "6372WR6ijO4DwTwaAlrLlyuJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SK_2147750723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SK!MTB"
        threat_id = "2147750723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 33 c9 8b d9 03 d8 73 05 e8 da 38 f9 ff 30 13 41 81 f9 47 5c 00 00 75 ea}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SN_2147750829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SN!MTB"
        threat_id = "2147750829"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 1c 01 30 13 41 81 f9 6f 5a 00 00 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SO_2147751257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SO!MTB"
        threat_id = "2147751257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 45 ff ff 75 f8 5a 30 02 83 45 f8 01 73 05 e8 8a 85 f9 ff 49 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VVB_2147751282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VVB!MTB"
        threat_id = "2147751282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "VLPSe1LbbQB4Drd9OVVRr053" wide //weight: 1
        $x_1_3 = "GFZFimxpjXbnQlkifMdd33122" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VVB_2147751282_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VVB!MTB"
        threat_id = "2147751282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "JP9MLdPtM3PaUlduMq236Bsid10lcUd183" wide //weight: 1
        $x_1_3 = "wFiCGnPdupFdebyaPfWuz7lxZrQO8pZu0l3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VVB_2147751282_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VVB!MTB"
        threat_id = "2147751282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "N844Ep4VQP7b3oYaH0L3uxLDp6ldOHoRO1DPZu39" wide //weight: 1
        $x_1_3 = "Vw2IrIvra1mVQOGWZ9LOo6AvZxTYJ4bH0dcyZ65" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VVB_2147751282_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VVB!MTB"
        threat_id = "2147751282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "g4VKBL19seOvvY4uwk8b28KovKedo50" wide //weight: 1
        $x_1_3 = "LtOyyxw0HOKi2nF3yKWhXrozoAVirWCi32" wide //weight: 1
        $x_1_4 = "Qu8U7OSIOC8cQotvhitDJKV76n06w172" wide //weight: 1
        $x_1_5 = "FlsFCpLrqO234" wide //weight: 1
        $x_1_6 = "X0Xze240" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VVB_2147751282_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VVB!MTB"
        threat_id = "2147751282"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "OLI4kO3RQTbKF9mr10gCcE193" wide //weight: 1
        $x_1_3 = "vdwOZert6XiVNQUEiB4WcIww1YUaQpbTiq94Lfi3OsTQUXidn190" wide //weight: 1
        $x_1_4 = "DHj0wFRnEIyTvjEa100" wide //weight: 1
        $x_1_5 = "aIUsjnNn7DfwjkABcD2mKF7T147" wide //weight: 1
        $x_1_6 = "opgpvyBjh12NL1XsK14" wide //weight: 1
        $x_1_7 = "tclTpNzub7VFbO3NlPH3iblfzZd2jJrhZJAG101" wide //weight: 1
        $x_1_8 = "Dm3CuM30hO4YFZKvxfCaYT6IyLZTPI0x9jLRDMS6pfmhc7gk386" wide //weight: 1
        $x_1_9 = "Likxlii0gYk09UUfFJA9wUa89" wide //weight: 1
        $x_1_10 = "BP6MT1t8KWwPodpeb0LiUlv17OYdWpexXIC107" wide //weight: 1
        $x_1_11 = "h7qu8ziutLmF8veVVDvm8EK1cATV208" wide //weight: 1
        $x_1_12 = "u42MymSczI0Aprb7LE0FrYk71F8aM2113" wide //weight: 1
        $x_1_13 = "x3bdydnWLF1dBr9Jxpa7hJGohuwQjx9UzHaxK7eGBU13z19" wide //weight: 1
        $x_1_14 = "lw3bSUd4neZJEUHwHIFRmZkB4ePKYNBfeXpb242" wide //weight: 1
        $x_1_15 = "R69UlxlYqKGiGteItgFinVRrYePdVQOU7CITj167" wide //weight: 1
        $x_1_16 = "Dby6uk8v2Go0Qz9KOhmr8n6kliTrLaeW201" wide //weight: 1
        $x_1_17 = "WtL8wiSjClWKLRP53jDkwuC1EHrzhixVAtStwhV9hRORfYO90" wide //weight: 1
        $x_1_18 = "sulAi0Oi4gDnzSKv2dOhYLd119" wide //weight: 1
        $x_1_19 = "U5illoPICIGWRtbke1QJdH227" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_VBB_2147751354_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VBB!MTB"
        threat_id = "2147751354"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_1_2 = "eBiJ3FPhkniif1p17u7UIdCFSvwMk4k2IJ9sZ79" wide //weight: 1
        $x_1_3 = "TJowMm0zggnl254" wide //weight: 1
        $x_2_4 = "FYAyYGQQ4BBlD49" wide //weight: 2
        $x_2_5 = "Od73xBzdNSTYwZSnAf6SJ6P74aMavrsOESAiVaJ122" wide //weight: 2
        $x_2_6 = "QHwFl9AriLHuc0h7x177" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_AN_2147752330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.AN!MTB"
        threat_id = "2147752330"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 0f 6e c6 [0-16] 66 0f 6e c9 [0-16] 66 0f 57 c8 [0-16] 66 0f 7e c9 [0-16] 39 c1 75 ?? [0-32] b8 ?? ?? ?? ?? [0-21] 05 [0-21] 8b 00 [0-21] 68 ?? ?? ?? ?? [0-21] 5b [0-21] 81 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_AE_2147752384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.AE!MTB"
        threat_id = "2147752384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f 7e da 3d [0-53] [0-21] 46 [0-21] 8b 17 [0-21] 0f 6e fe [0-21] 0f 6e da [0-21] 0f ef df [0-21] c3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fareit_AE_2147752384_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.AE!MTB"
        threat_id = "2147752384"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f 7e da 85 [0-53] [0-21] 46 [0-21] 8b 17 [0-21] 0f 6e fe [0-21] 0f 6e da [0-21] 0f ef df [0-21] c3}  //weight: 3, accuracy: Low
        $x_3_2 = {0f 7e da 66 [0-53] [0-21] 46 [0-21] 8b 17 [0-21] 0f 6e fe [0-21] 0f 6e da [0-21] 0f ef df [0-21] c3}  //weight: 3, accuracy: Low
        $x_3_3 = {0f 7e da 81 [0-53] [0-21] 46 [0-21] 8b 17 [0-21] 0f 6e fe [0-21] 0f 6e da [0-21] 0f ef df [0-21] c3}  //weight: 3, accuracy: Low
        $x_3_4 = {0f 7e da 3d [0-37] [0-21] 46 [0-21] 8b 17 [0-21] 0f 6e fe [0-21] 0f 6e da [0-21] 0f ef df [0-21] c3}  //weight: 3, accuracy: Low
        $x_3_5 = {0f 7e da 83 [0-53] [0-21] 46 [0-21] 8b 17 [0-21] 0f 6e fe [0-21] 0f 6e da [0-21] 0f ef df [0-21] c3}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fareit_RC_2147752396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RC!MTB"
        threat_id = "2147752396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 01 88 45 fb 8b 55 fc 8a 45 fb 88 02 b0 31 30 02 83 45 fc 01 73 05 e8 cb a2 f9 ff ff 45 f4 41 81 7d f4 a9 59 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RC_2147752396_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RC!MTB"
        threat_id = "2147752396"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 51 0c 8b 8d 78 ff ff ff 8b b5 70 ff ff ff 8a 04 08 32 04 32 8b 4d cc 8b 51 0c 8b 8d 68 ff ff ff 88 04 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RQS_2147752419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RQS!MTB"
        threat_id = "2147752419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MSVBVM60.DLL" ascii //weight: 2
        $x_2_2 = "TgMHhwZuZtcWIjVgowMwpjca0dBK12H1167" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_N_2147752440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.N!MTB"
        threat_id = "2147752440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d9 d0 8b 04 0a 01 f3 0f 6e c0 0f 6e 0b 0f ef c1 51 0f 7e c1 88 c8 59 29 f3 83 c3 01 75 02 89 fb 89 04 0a 83 c1 01 75 d8}  //weight: 1, accuracy: High
        $x_1_2 = {81 ec 00 02 00 00 55 89 e5 e8 00 00 00 00 58 83 e8 0e 89 45 44 e8 9e 27 00 00 85 c9 e9 b5 19 00 00 59 89 4d 18 39 c9 b8 39 05 00 00 ba 6d 07 af 60 e8 a9 22 00 00 89 85 98 00 00 00 e9 b1 19 00 00 fc 59 ba c5 dc cf 94 e8 92 22 00 00 eb 1c 85 ff 5b 31 d2 52 54 53 85 db ff d0 58 83 f8 0c 7d 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fareit_N_2147752440_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.N!MTB"
        threat_id = "2147752440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hUAWEA" wide //weight: 1
        $x_1_2 = "DAC technolOgIES" wide //weight: 1
        $x_1_3 = "CAm sTUDIO grouO" wide //weight: 1
        $x_1_4 = "SOURCo fIRA, gnr." wide //weight: 1
        $x_1_5 = "WORle" wide //weight: 1
        $x_1_6 = "ZALLO CRe Jeca" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SV_2147752451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SV!MTB"
        threat_id = "2147752451"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 43 4e 75 17 00 8b cf b2 ?? 8a 03 e8 af ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {32 c2 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_TD_2147752577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.TD!MTB"
        threat_id = "2147752577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 6e fe 66 [0-21] 0f 6e da [0-21] 31 f2 [0-21] c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SW_2147752664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SW!MTB"
        threat_id = "2147752664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 08 80 f1 82 8b 5d fc 03 da 73 05 e8 2b c0 f9 ff 88 0b 42 40 81 fa dd 5f 00 00 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VX_2147753375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VX!MTB"
        threat_id = "2147753375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {85 c0 31 f7 66 83 f8 ?? 66 85 d2 85 ff 66 81 fa ?? ?? 89 3c 10 66 85 db 85 ff 81 fb ?? ?? ?? ?? 66 a9 ?? ?? 5f 85 db 85 db 66 a9 ?? ?? 66 3d ?? ?? 83 c2 ?? 66 83 ff ?? 66 81 fb ?? ?? 83 fb ?? 85 d2 83 c7 ?? 85 c0 66 85 db 66 85 d2 81 fa ?? ?? ?? ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RQ_2147753379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RQ!MTB"
        threat_id = "2147753379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {32 c2 88 01 c3 8d 40 00 55 8b ec 51 89 45 ?? 8b 7d ?? 81 c7 ?? ?? ?? ?? ff d7 59 5d c3 8d 40 00 55 8b ec 51 53 56 57 6a ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_DG_2147753797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.DG!MTB"
        threat_id = "2147753797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fb 6a 09 66 81 ff 9e 77 66 85 d2 81 fb af 70 3b 39 66 3d 3f 03 85 d2 eb 03 00 00 00 ff e0 66 81 fb 84 77 66 85 d2 85 d2 0f 6e da 81 fb 5e 9a 55 f4 31 f1 66 85 d2 eb 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_OF_2147753798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.OF!MTB"
        threat_id = "2147753798"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 81 fa 81 7f f5 41 81 fb d2 b6 5e 1b 85 db 66 81 fb ae 75 66 85 d2 ff e0 eb 02 00 00 81 ff 9f 7f b5 d9 81 ff a4 d0 62 ab 85 c0 66 81 fa 97 f5 0f 6e da 66 85 d2 31 f1 81 ff ff 1c d6 a1 eb 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_PRB_2147753898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.PRB!MTB"
        threat_id = "2147753898"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C6h1uLOa1omsDqXOis7P6KpL3QrV353" wide //weight: 1
        $x_1_2 = "YBTmaBsg0IpQ8WhRor9qy2" wide //weight: 1
        $x_1_3 = "rQzfBwi3tnBS9bWNIJKbosAT244" wide //weight: 1
        $x_1_4 = "ivO30vEdNHHqkPh3zWOasTh2a6Z196" wide //weight: 1
        $x_1_5 = "rdsZNFSH6I4jVuhstcmQDXwblPfl8XwEZgi121" wide //weight: 1
        $x_1_6 = "MOrtisClod" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RDL_2147754210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RDL!MTB"
        threat_id = "2147754210"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "oreGKuTxZEZHl35" wide //weight: 1
        $x_1_2 = "DkP126JLFQTnK9v7Zf2oM61" wide //weight: 1
        $x_1_3 = "D4zFNtWZKg1IUUVLG3gGukKz2iee1L174" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_MM_2147754293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.MM!MTB"
        threat_id = "2147754293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {76 05 e8 6d 3d f9 ff 8b 84 85 e4 fb ff ff 33 d2 8a 55 f7 33 c2 3d ff 00 00 00 76 05 e8 53 3d f9 ff 8b 55 e8 88 ?? ?? 47 ff 4d e4 0f 85 94}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_FF_2147754347_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.FF!MTB"
        threat_id = "2147754347"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 84 85 e4 fb ff ff 33 d2 8a 55 f7 33 c2 3d ?? ?? ?? ?? 76 ?? e8 ?? ?? ?? ?? 8b 55 e8 88 02 ?? 47 ff 4d e4 0f 85}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_DZ_2147754349_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.DZ!MTB"
        threat_id = "2147754349"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 50 8b 45 e8 99 e8 ?? ?? ?? ?? 71 ?? e8 ?? ?? ?? ?? ?? 33 d2 8a 55 ef 33 94 85 ?? ?? ?? ?? 8b 45 f0 88 10 ff 45 f4 46 ff 4d e0 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_JS_2147755385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.JS!MTB"
        threat_id = "2147755385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 d2 8a 55 ?? 33 94 85 ?? ?? ?? ?? 8b 45 ?? 88 10 ff 45 ?? 46 ff 4d ?? 0f 85 37 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_IT_2147755896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.IT!MTB"
        threat_id = "2147755896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 31 d2 [0-48] 80 34 01 ?? ff 45 fc 41 89 d7 39 f9 ?? ?? 05 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_GM_2147757336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.GM!MTB"
        threat_id = "2147757336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 c9 31 d2 6a ?? 5e 81 c6 [0-4] 87 d6 80 34 01 ?? 41 89 d3 39 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_GM_2147757336_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.GM!MTB"
        threat_id = "2147757336"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 83 e1 [0-48] 8a 0a 80 f1 4a 8b 5d ?? 03 d8 88 0b [0-48] 8b 4d ?? 03 c8 8a 1a 88 19 40 42 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SS_2147758035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SS!MTB"
        threat_id = "2147758035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 7d fc 00 76 34 8b 45 fc bf 05 00 00 00 33 d2 f7 f7 85 d2 75 14 8a 01 34 7c 8b d3 03 55 fc 73 05 e8 36 72 f7 ff 88 02 eb 10 8b c3 03 45 fc 73 05 e8 26 72 f7 ff 8a 11 88 10 ff 45 fc 41 81 7d fc 67 92 00 00 75 b9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SS_2147758035_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SS!MTB"
        threat_id = "2147758035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 fc 03 f7 8a 03 88 45 fb 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 fb 32 45 fa 88 06 8a 06 32 45 f9 88 06 eb 05 8a 45 fb 88 06 47 43 49 75 ca}  //weight: 2, accuracy: High
        $x_1_2 = {75 11 8a 45 ?? 32 45 ?? 88 06 8a 06 32 45 ?? 88 06 eb 05 8a 45 ?? 88 06 47 43 49 75 ca}  //weight: 1, accuracy: Low
        $x_2_3 = {8b 75 fc 03 f7 8a 03 88 45 fa 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 fa 32 45 fb 88 06 8a 06 32 45 f9 88 06 eb 05 8a 45 fa 88 06 47 43 49 75 ca}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_SS_2147758035_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SS!MTB"
        threat_id = "2147758035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 5d f8 03 de 8a 01 88 45 f7 8b c6 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 f7 32 45 f5 88 03 8a 03 32 45 f6 88 03 eb 05 8a 45 f7 88 03 46 41 4f 75 ca}  //weight: 2, accuracy: High
        $x_2_2 = {8b 5d f8 03 de 8a 01 88 45 f6 8b c6 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 f6 32 45 f5 88 03 8a 03 32 45 f7 88 03 eb 05 8a 45 f6 88 03 46 41 4f 75 ca}  //weight: 2, accuracy: High
        $x_1_3 = {8b 5d f8 03 de 8a 01 88 45 [0-4] 8b c6 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 [0-4] 32 45 f5 88 03 8a 03 32 45 [0-4] 88 03 eb 05 8a 45 [0-4] 88 03 46 41 4f 75 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_SS_2147758035_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SS!MTB"
        threat_id = "2147758035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 75 fc 03 f7 8a 03 88 45 fa 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 fa 32 45 f9 88 06 8a 06 32 45 fb 88 06 eb 05 8a 45 fa 88 06 47 43 49 75 ca}  //weight: 2, accuracy: High
        $x_2_2 = {8b 75 fc 03 f7 8a 03 88 45 f9 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 f9 32 45 fa 88 06 8a 06 32 45 fb 88 06 eb 05 8a 45 f9 88 06 47 43 49 75 ca}  //weight: 2, accuracy: High
        $x_1_3 = {8b 75 fc 03 f7 8a 03 88 45 [0-2] 8b c7 51 b9 03 00 00 00 33 d2 f7 f1 59 85 d2 75 11 8a 45 [0-2] 32 45 [0-2] 88 06 8a 06 32 45 fb 88 06 eb 05 8a 45 [0-2] 88 06 47 43 49 75 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_SS_2147758035_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SS!MTB"
        threat_id = "2147758035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {83 7d ec 00 76 36 8b 45 ec b9 05 00 00 00 33 d2 f7 f1 85 d2 75 15 8b 45 ec 8a 80 a8 3e 46 00 34 4f 8b 55 fc 03 55 ec 88 02 eb 11 8b 45 ec 8a 80 a8 3e 46 00 8b 55 fc 03 55 ec 88 02 ff 45 ec 81 7d ec 21 80 00 00 75 b8}  //weight: 2, accuracy: High
        $x_2_2 = {83 7d e8 00 76 36 8b 45 e8 b9 05 00 00 00 33 d2 f7 f1 85 d2 75 15 8b 45 e8 8a 80 4c af 46 00 34 99 8b 55 fc 03 55 e8 88 02 eb 11 8b 45 e8 8a 80 4c af 46 00 8b 55 fc 03 55 e8 88 02 ff 45 e8 81 7d e8 24 8b 00 00 75 b8}  //weight: 2, accuracy: High
        $x_1_3 = {76 36 8b 45 [0-4] b9 05 00 00 00 33 d2 f7 f1 85 d2 75 15 8b 45 [0-4] 8a 80 4c af 46 00 34 99 8b 55 fc 03 55 [0-4] 88 02 eb 11 8b 45 [0-4] 8a 80 4c af 46 00 8b 55 fc 03 55 [0-4] 88 02 ff 45 [0-4] 81 7d [0-4] [0-8] 75 b8}  //weight: 1, accuracy: Low
        $x_2_4 = {83 7d e8 00 76 36 8b 45 e8 [0-21] 75 15 8b 45 e8 8a 80 [0-6] 34 ?? 8b 55 fc 03 55 e8 88 02 eb 11 8b 45 e8 8a 80 01 8b 55 fc 03 55 e8 88 02 ff 45 e8 81 7d e8 [0-6] 75 b8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_BD_2147758164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.BD!MTB"
        threat_id = "2147758164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e c7 45 64 ?? ?? 00 00 31 c9 31 ff 09 c7 ad 31 04 0f 83 e9 fc 81 f9 ?? ?? 00 00 75 f1 bb ?? ?? ?? ?? 31 d2 83 f2 04 31 1c 0f 29 d1 7d f4 ff e7}  //weight: 1, accuracy: Low
        $x_1_2 = {ad 83 f8 00 74 fa 81 38 ?? ?? ?? ?? 75 f2 81 78 04 ?? ?? ?? ?? 75 e9 31 db 53 53 53 54 68 00 00 04 00 52 51 54 89 85 ?? 00 00 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_GA_2147758264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.GA!MTB"
        threat_id = "2147758264"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cFEUagAeaEuvA161" wide //weight: 1
        $x_1_2 = "standardudstyrenes" wide //weight: 1
        $x_1_3 = "Defectious9" wide //weight: 1
        $x_1_4 = "lcDvQ110" wide //weight: 1
        $x_1_5 = "SPRINGLAGENET" wide //weight: 1
        $x_1_6 = "overskudssamfund" wide //weight: 1
        $x_1_7 = "heltalsvaerdier" wide //weight: 1
        $x_1_8 = "FLADERNE" wide //weight: 1
        $x_1_9 = "oregonpine" wide //weight: 1
        $x_1_10 = "INTIMIDERES" wide //weight: 1
        $x_1_11 = "MSVBVM60.DLL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_KL_2147760428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.KL"
        threat_id = "2147760428"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 8a 45 ef 33 84 8d e4 fb ff ff 88 06 [0-16] [0-21] 46 ff 4d e4 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 85 e4 fb ff ff [0-16] [0-16] [0-16] 89 18 [0-32] 43 83 c0 04 81 fb 00 01 00 00 75 dc 8b 5d f0 81 fb ff 00 00 00 0f 8f a6 00 00 00 8d b4 9d e4 fb ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 84 bd e4 fb ff ff 89 06 [0-32] 8a c2 89 84 bd e4 fb ff ff 43 83 c6 04 81 fb 00 01 00 00 0f 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_AKN_2147768548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.AKN!MTB"
        threat_id = "2147768548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 5e 96 f7 f0 8b c6 5e 5b c3 3f 00 6a 00 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {32 45 fb 88 06 8a 06 32 45 f9 88 06 eb [0-4] 8a 45 fa 88 06 47 43 49 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RF_2147775879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RF!MTB"
        threat_id = "2147775879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 f2 ed c5 30 4f 92 30 62 5d 13 e0 17 f2 8d dd 77 a5}  //weight: 5, accuracy: High
        $x_1_2 = "Iscobaquebu.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RF_2147775879_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RF!MTB"
        threat_id = "2147775879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 52 50 a1 ?? ?? ?? ?? 8b 40 ?? 99 03 04 24 13 54 24 ?? 83 c4 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 06 8b 00 25 ff ff 00 00 50 a1 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8b 16 89 02 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RF_2147775879_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RF!MTB"
        threat_id = "2147775879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@*\\AProject1" ascii //weight: 1
        $x_1_2 = "185.7.214.7/ADS11/RED.PNG" ascii //weight: 1
        $x_1_3 = "https://iplogger.org/1pucu7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RF_2147775879_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RF!MTB"
        threat_id = "2147775879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 34 07 7c b1 6a 45 66 83 c0 00 f3 0f 7e ec 66 0f 6e d9 66 0f}  //weight: 1, accuracy: High
        $x_1_2 = "Folkebibliotekerne2" ascii //weight: 1
        $x_1_3 = "Superrighteously6" ascii //weight: 1
        $x_1_4 = "Teknologivurderingsprojektet9" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Fareit_RF_2147775879_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RF!MTB"
        threat_id = "2147775879"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {88 f5 81 34 37 1a 33 e5 b5 90 d9 eb eb 2e 6d 99}  //weight: 5, accuracy: High
        $x_1_2 = "IebGksAxUx4cT4pGdUyoOdFd2FgXzZDWwMFUF229" ascii //weight: 1
        $x_1_3 = "t8muoNmL2EFu6YwPEMRJqgcscpIlvQxOE2186" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RT_2147782305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RT!MTB"
        threat_id = "2147782305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 f7 c7 bb ce 37 83 ff 6f 81 ff aa 00 00 00 9b db e3 66 0f 62 c8 dd c0 66 0f db e7 66}  //weight: 1, accuracy: High
        $x_1_2 = {89 3b 81 fe a3 00 00 00 3d fc 00 00 00 c7 44 24 ?? 9d 00 00 00 83 fa 62 66}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RT_2147782305_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RT!MTB"
        threat_id = "2147782305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yTHIAFZkwO055RNbIp8xM6zQd155" ascii //weight: 1
        $x_1_2 = "Intervalhyppigheder" ascii //weight: 1
        $x_1_3 = "Skulderbladets1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RT_2147782305_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RT!MTB"
        threat_id = "2147782305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rumenaxkeweranskxme" ascii //weight: 1
        $x_1_2 = "txtPassword" ascii //weight: 1
        $x_1_3 = "wanumesfrscsasfv2" ascii //weight: 1
        $x_1_4 = "arenaoskumnfses" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RT_2147782305_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RT!MTB"
        threat_id = "2147782305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6////6/61661" ascii //weight: 1
        $x_1_2 = "Prologklausulens5" ascii //weight: 1
        $x_1_3 = "Forflyttelsernes7" ascii //weight: 1
        $x_1_4 = "Miljbeskyttelsesreglement" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RT_2147782305_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RT!MTB"
        threat_id = "2147782305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOOKHERE" ascii //weight: 1
        $x_1_2 = "UnregisterHotKey" ascii //weight: 1
        $x_1_3 = "Unvulgarizes" ascii //weight: 1
        $x_1_4 = "Millisekunds" ascii //weight: 1
        $x_1_5 = "BLOODSUCKING" ascii //weight: 1
        $x_1_6 = "Fakeers" ascii //weight: 1
        $x_1_7 = "Bankdirektrs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RT_2147782305_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RT!MTB"
        threat_id = "2147782305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "diskspecifikationens" ascii //weight: 2
        $x_2_2 = "Reprsentantskabsmdets8" ascii //weight: 2
        $x_1_3 = "folkekomedierne" ascii //weight: 1
        $x_2_4 = "Koncentrationslejr6" ascii //weight: 2
        $x_2_5 = "Strukturalistens7" ascii //weight: 2
        $x_1_6 = "Beregningsenheders1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_RT_2147782305_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RT!MTB"
        threat_id = "2147782305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "feawefeasfdcsfe" ascii //weight: 1
        $x_1_2 = "afwescxfscvkfeasla" ascii //weight: 1
        $x_1_3 = "CEaElElEWEiEnEdEoEwEPErEoEcEWE" ascii //weight: 1
        $x_1_4 = "GQeQtQMQoQdQuQlQeQHQaQnQdQlQeQWQ" ascii //weight: 1
        $x_1_5 = "C7r7y7p7t7D7e7c7r7y7p7t7" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RT_2147782305_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RT!MTB"
        threat_id = "2147782305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Flygtningesudspil" ascii //weight: 1
        $x_1_2 = "stenknuserens" ascii //weight: 1
        $x_1_3 = "Antidisestablishmentarianism" ascii //weight: 1
        $x_1_4 = "UNPROVIDEDLYREKLAM" ascii //weight: 1
        $x_1_5 = "Aktieposternesjageriernepro5" ascii //weight: 1
        $x_1_6 = "DANSKLRERFORENIN" ascii //weight: 1
        $x_1_7 = "magistratsregering" ascii //weight: 1
        $x_1_8 = "Fluorskyldningers2" ascii //weight: 1
        $x_1_9 = "Afmrkninger1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Fareit_RT_2147782305_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RT!MTB"
        threat_id = "2147782305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "h5z7qKyBWCXw1ag0BBCcww3wSH35EbknHBM120" wide //weight: 2
        $x_2_2 = "Bibliomanianism3" wide //weight: 2
        $x_1_3 = "Beskrivelsesvrktjet" wide //weight: 1
        $x_2_4 = "Kefmunaedsfxecsds" ascii //weight: 2
        $x_2_5 = "euisfdjsxadfds7" ascii //weight: 2
        $x_1_6 = "+bWMPLibCtl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_RT_2147782305_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RT!MTB"
        threat_id = "2147782305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bortforpagtningerne" ascii //weight: 1
        $x_2_2 = "gfhttpQ0tQqQtziexUR1WE3vCxWuXWGCOSA105" wide //weight: 2
        $x_2_3 = "lQfH5D0iVzc0aXXh4nCPZ1CeTp193" wide //weight: 2
        $x_2_4 = "BoeMSy7oA6NGZfqJeIH5SOwyUJ6169" wide //weight: 2
        $x_2_5 = "Kondenseres1" wide //weight: 2
        $x_1_6 = "Shakespeareans7" wide //weight: 1
        $x_2_7 = "ntMUJqllkpaSaEf" ascii //weight: 2
        $x_2_8 = "fpYYKLmvHkDiGZkZVP" ascii //weight: 2
        $x_1_9 = "pLYmTlQbBpmgyvSoM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_SB_2147782930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SB!MTB"
        threat_id = "2147782930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "frustum" ascii //weight: 3
        $x_3_2 = "txtPassword" ascii //weight: 3
        $x_3_3 = "cmdCancel" ascii //weight: 3
        $x_3_4 = "chkLoadTipsAtStartup" ascii //weight: 3
        $x_3_5 = "{Home}+{End}" ascii //weight: 3
        $x_3_6 = "3D_maze" ascii //weight: 3
        $x_3_7 = "TIPOFDAY.TXT" ascii //weight: 3
        $x_3_8 = "TROCBITS120" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SM_2147783697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SM!MSR"
        threat_id = "2147783697"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b ca 99 f7 f9 42 8b 45 f8 8a 44 10 ff 32 07 88 07}  //weight: 1, accuracy: High
        $x_1_2 = "c:TSeK746f61373a35333931313838cacc3935" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RW_2147784699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RW!MTB"
        threat_id = "2147784699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 7c 30 fc [0-15] 5d [0-10] 81 f7 [0-18] 57 [0-10] 8f 44 30 fc [0-25] d9}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 7c 10 fc [0-15] 5d [0-10] 81 f7 [0-18] 57 [0-10] 8f 44 10 fc [0-25] d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fareit_RW_2147784699_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RW!MTB"
        threat_id = "2147784699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "V_i_r_t_u_a_l_P_r_o_t_e_c_t_" ascii //weight: 1
        $x_1_2 = "C2r2y2p2t2D2e2s2t2r2o2y2K2e2y2" ascii //weight: 1
        $x_1_3 = "VDiDrDtDuDaDlDADlDlDoDcDEDxD" ascii //weight: 1
        $x_1_4 = "owedmesa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_O_2147786795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.O!MTB"
        threat_id = "2147786795"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SHAKSMER" ascii //weight: 1
        $x_1_2 = "OFFTHERECORD-32.dll" ascii //weight: 1
        $x_1_3 = "COVi-TEK" wide //weight: 1
        $x_1_4 = "SURiNamI" wide //weight: 1
        $x_1_5 = "VIVUSbLOCada ltd." wide //weight: 1
        $x_1_6 = "BOShiYUKi MASUi" wide //weight: 1
        $x_1_7 = "IkARUS SEcUrItY SOFtwaRe GmbH" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_FT_2147787044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.FT!MTB"
        threat_id = "2147787044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ASTOnsoft LCd." wide //weight: 1
        $x_1_2 = "cc TOOLS" wide //weight: 1
        $x_1_3 = "METAGEek," wide //weight: 1
        $x_1_4 = "TELEGram MESSEnger" wide //weight: 1
        $x_1_5 = "NORMAn SAFEground Aa" wide //weight: 1
        $x_1_6 = "EPSON" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_FU_2147787045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.FU!MTB"
        threat_id = "2147787045"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SaMSTUdiO CRouA" wide //weight: 1
        $x_1_2 = "ZANON" wide //weight: 1
        $x_1_3 = "TOURcefiRe, VNA." wide //weight: 1
        $x_1_4 = "THunderbirD" wide //weight: 1
        $x_1_5 = "AUDACITy soaX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_FV_2147787046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.FV!MTB"
        threat_id = "2147787046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 16 8d b6 01 00 00 00 66 23 cd 32 d3 fe ca 80 f2 d7 66 d3 c9 f9 f6 d2 c1 c9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_FV_2147787046_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.FV!MTB"
        threat_id = "2147787046"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kalkada" ascii //weight: 1
        $x_1_2 = "mntrRGB XYZ" ascii //weight: 1
        $x_1_3 = "XNruZUjDHXgeQOQyBdYgYqWrbzNmkVIZpqWGQvKzuqxdQIbyKfKSzKdHwUUIXQQdxmrbAgBmBIqQDYlyEbmRQqwJRCurmYfLgBJj" wide //weight: 1
        $x_1_4 = "public stub posleden" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_PD_2147787395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.PD!MTB"
        threat_id = "2147787395"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "IPOrA hOFTwaRE isE" wide //weight: 1
        $x_1_2 = "iSTOnSOFt ltE." wide //weight: 1
        $x_1_3 = "cASTpASS" wide //weight: 1
        $x_1_4 = "oMSIsOFT ImbA" wide //weight: 1
        $x_1_5 = "kAVAsoFT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_Ch_2147787626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.Ch!MTB"
        threat_id = "2147787626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b7 58 06 4b 85 db 7c 54 43 c7 06 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_Chl_2147787627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.Chl!MTB"
        threat_id = "2147787627"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 8d 83 91 01 00 00 a1 ?? ?? ?? ?? 8b 40 28 03 07 a3 ?? ?? ?? ?? 05 dd 03 00 00 29 c3 0f af ca 6a 00 6a 01 8b 07 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RM_2147787675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RM!MTB"
        threat_id = "2147787675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iO%WL1nN*XL7kF1sB1qR1WEHeFCmJ9pJC" ascii //weight: 1
        $x_1_2 = "Fake Connects" ascii //weight: 1
        $x_1_3 = "http://www.ssnbc.com/wiz/" ascii //weight: 1
        $x_1_4 = "PasswordStr" ascii //weight: 1
        $x_1_5 = "PayLoad" ascii //weight: 1
        $x_1_6 = "ProcInject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RM_2147787675_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RM!MTB"
        threat_id = "2147787675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Flertalsbeslutningens" ascii //weight: 2
        $x_2_2 = "Grundfunktionernes" ascii //weight: 2
        $x_1_3 = "udskriftsbetingelsens" wide //weight: 1
        $x_2_4 = "virksomhedslederens" ascii //weight: 2
        $x_2_5 = "Seismologiens7" wide //weight: 2
        $x_1_6 = "Epoxymalinger4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Fareit_CV_2147788165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.CV!MTB"
        threat_id = "2147788165"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4c 70 42 00 0c 71 42 00 5c 11 40 00 6c 72 42 00 62 11 40 00 d4 38 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RTH_2147788938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RTH!MTB"
        threat_id = "2147788938"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 89 45 ?? 8b 45 ?? 89 45 ?? 8b 45 ?? 33 d2 52 50 8b 45 ?? 8b 40 ?? 99 03 04 24 13 54 24 ?? 83 c4 08}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 07 8b 00 25 ff ff 00 00 50 56 e8 ?? ?? ?? ?? 8b 17 89 02 eb ?? 8b 45 ?? 83 c0 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_TST_2147789537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.TST!MTB"
        threat_id = "2147789537"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 c7 96 9d 00 4a f7 c6 79 a1 00 4a f7 c7 41 a4 00 4a f7 c7 29 a8 00 4a f7 c7 89 b2 00 4a f7 c5 f5 b5 00 4a f7 c5 de b9 00 4a f7 c7 bb bc 00 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_ASP_2147789538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.ASP!MTB"
        threat_id = "2147789538"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4e 15 b9 94 24 01 46 11 a3 ef d1 14 69 1a a5 84 c7 e6 f7 7e eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_PT_2147793436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.PT!MTB"
        threat_id = "2147793436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 cb 9c 8b 78 bf 9c 8b 78 a2 9c 8b 78 5d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_EGZV_2147793438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.EGZV!MTB"
        threat_id = "2147793438"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 80 81 cf f8 ef ed dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_ASDF_2147793667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.ASDF!MTB"
        threat_id = "2147793667"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3e b9 a6 07 f4 0f 34 21 38 e4 fc 2f 5a 97 79 f4}  //weight: 1, accuracy: High
        $x_1_2 = {38 7e 45 d2 ac 34 71 09 30 1c 11 c4 32 5c 76 4a 8d ab 46 6d 1c 98}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_ACS_2147793768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.ACS!MTB"
        threat_id = "2147793768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0f b6 42 03 0c 7f 83 c4 04 8b 44 28 85 03 80 3d fc ff ff 66 f7 d0 fc 33 c4 66 a9 ff ff fc 75 10}  //weight: 10, accuracy: High
        $x_10_2 = {83 e8 03 03 c1 03 d1 ba 18 00 00 00 3d fd 0f 00 00 0f 84 b0}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RTA_2147793787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RTA!MTB"
        threat_id = "2147793787"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Driftskontrolvilkaarene" ascii //weight: 1
        $x_1_2 = "SYGEMELDINGSBLANKETS" ascii //weight: 1
        $x_1_3 = "qN9qCdi1SvvwocWQESHnR1dnA12GAzVE3114" ascii //weight: 1
        $x_1_4 = "Photoisomerization4" ascii //weight: 1
        $x_1_5 = "Skattepligtsophret" ascii //weight: 1
        $x_1_6 = "Produktionsfejlenes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Fareit_HDFG_2147794539_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.HDFG!MTB"
        threat_id = "2147794539"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 9a 0b 28 85 99 0b 12 85 99 0b 2c 85 9b 0b 12 85 9b 0b 17 85 a5 0b 16 85 a1 0b 16 85 a3 0b 2a 85 a4 0b 16 85 a6 0b 29 85 9b 0b 2a 85 a0 0b 28 85 a5 0b 15 85 9c 0b 28 85 a3 0b 14 85 a5 0b 13 85 9a 0b 13 85 98 0b 2c 85 a5 0b 28 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RNDM_2147794616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RNDM!MTB"
        threat_id = "2147794616"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 64 35 66 75 6e 00 00 67 7a 69 70 44 65 63 6f 6d}  //weight: 1, accuracy: High
        $x_1_2 = {d2 43 00 e4 ad 43 00 1c a4 43 00 70 af 43 00 90 3d 45 00 5c 3c 45 00 a8 b0 43 00 08 3e 45 00 50 d3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_PKI_2147794934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.PKI!MTB"
        threat_id = "2147794934"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Bovista" wide //weight: 1
        $x_1_2 = "jBI7ywc5BHVriHYs2lFHtMnHlQtSEyCO33169" wide //weight: 1
        $x_1_3 = "Manioc" wide //weight: 1
        $x_1_4 = "SENGETJET" wide //weight: 1
        $x_1_5 = "Nonfeelingly" wide //weight: 1
        $x_1_6 = "Curl Lasting" wide //weight: 1
        $x_1_7 = "SPRINKLENDES" ascii //weight: 1
        $x_1_8 = "BEGGIATOACEAE" ascii //weight: 1
        $x_1_9 = "Predecided6" ascii //weight: 1
        $x_1_10 = "Omsadlingens1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_OKLM_2147795087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.OKLM!MTB"
        threat_id = "2147795087"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {14 11 40 00 fc 35 40 00 08 36 40 00 0c 36 40 00 10}  //weight: 1, accuracy: High
        $x_1_2 = {31 00 00 8b c0 90 90 8b 15 50 fc 48 00 88 02 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_POIU_2147795817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.POIU!MTB"
        threat_id = "2147795817"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4a 73 04 89 f3 89 f8 71 0a 0c 8d ff c6 f7 c2 14 3c e5 0e 0f b7 db 43 80 e8 2a 81 fa 85 00 00 00 0f 8f da ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {bf 40 67 0e 00 0f b6 d2 80 ea 97 81 c7 bd 02 00 00 1d 4b 11 6d a4 80 c6 9a 0f af c1 8d 1f 2b f5 8b c0 81 f3 c7 61 0e 00 80 f2 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fareit_POIV_2147795818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.POIV!MTB"
        threat_id = "2147795818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a8 16 40 00 1f ?? ?? ?? ce 2c 41 00 d5 2c 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_PLK_2147795825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.PLK!MTB"
        threat_id = "2147795825"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a d8 8a d0 24 f0 c0 e3 06 0a 5c 0f 02 c0 e0 02 0a 04 0f 80 e2 fc c0 e2 04 0a 54 0f 01 88 5d ff 8b 5d f8 88 04 1e 8a 45 ff 46 88 14 1e 46 88 04 1e 8b 45 0c 83 c1 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RPB_2147795854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RPB!MTB"
        threat_id = "2147795854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be ff ff ff 0f bf 01 00 00 00 6a 00 ff 15 ?? ?? ?? ?? 2b f7 75 f4 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 29 05 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 1b ca 3b c8 89 0d ?? ?? ?? ?? 7c ?? 7f 20 00 [0-32] ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = {6b 00 45 00 72 00 6e 00 45 00 6c 00 33 00 32 00 2e 00 44 00 4c 00 4c 00 00 00 00 00 6b 45 72 6e 45 6c 33 32 2e 44 4c 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_DRLO_2147796176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.DRLO!MTB"
        threat_id = "2147796176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 14 13 44 5b 14 13 4c 5b 14 13 54 5b 14 13 5c 5b 14 13 64 5b 14 13 6c 5b 14 13 74 5b 14 13 7c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_DRLP_2147796177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.DRLP!MTB"
        threat_id = "2147796177"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 00 02 2f 33 ca 52 e5 ed 8b 4e bc ef 3c e0 21 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_OP_2147796179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.OP!MTB"
        threat_id = "2147796179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f8 89 45 f4 8b 45 fc 90 03 45 f8 90 8a 18 90 80 f3 e6 88 18 90 90 ff 45 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_OP_2147796179_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.OP!MTB"
        threat_id = "2147796179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d f3 fc d6 7a 7a 7a 92 c5 8e 85 85 12 21 0f f0 8a 2d f3 3c 36 92 cb 8e 85 85 f1 a2 12 1e fc 89 0f 2d f3 24 32 92 db 8e 85 85 f3 3c 4e 12 d8 dc 1b 91 2d 92 e9 8e 85 85 12 af 35 1e 58 2d f3 3c 42 92 ff 8e 85 85 12 03 54 b9 ee 2d f3 3c 46 92 0d 8e 85 85 12 cb 72 7e 8d 2d 93 39 9c 85 85 ea ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_OTYT_2147797370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.OTYT!MTB"
        threat_id = "2147797370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 fc 03 d3 8a 12 80 f2 56 8b 4d fc 03 c8 88 11 ff 45 fc 81 7d fc 9a 59 00 00 75 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_GF_2147797776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.GF!MTB"
        threat_id = "2147797776"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 30 2e 64 6c 6c 00 ba db 00 51 d4 d0 20 ee d2 4e dc 74}  //weight: 1, accuracy: High
        $x_1_2 = {46 f5 2b 48 34 6e c1 0b 30 66 da c0 51 5b fa 1a 79 a0 6d 09 f0 f3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Fareit_IPED_2147797781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.IPED!MTB"
        threat_id = "2147797781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {47 00 f4 31 47 00 38 31 47 00 08 34 47 00 d8 33 47 00}  //weight: 1, accuracy: High
        $x_1_2 = {88 18 eb 16 90 90 90 8b 45 fc 90 90 03 45 f8 90 90 8a 18 90 90 80 f3 81 eb e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_INH_2147798660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.INH!MTB"
        threat_id = "2147798660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3c b7 37 33 33 33 63 cc 65 3b 59 77 00 cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_INF_2147799509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.INF!MTB"
        threat_id = "2147799509"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 95 84 ea ff ff 8a 00 8d 0c 8a 03 8d 90 ea ff ff 8b 95 ac ea ff ff 89 8d b4 ea ff ff 8b 8d b8 ea ff ff 88 04 11 41 3b 8d b0 ea ff ff 89 8d b8 ea ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_VBN_2147799514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.VBN!MTB"
        threat_id = "2147799514"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {90 89 1e a1 f0 cb 46 00 03 06 8a 00 90 90 34 2b 8b 15 f0 cb 46 00 03 16 88 02 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_FTR_2147799515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.FTR!MTB"
        threat_id = "2147799515"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 45 08 18 4e 50 54 81 6d 88 89 d4 9f 03 81 45 f0 27 b5 37 58 b8 8d bf d9 75 f7 65 8c 8b 45 8c 81 ad cc fe ff ff 68 6c 98 55 89 75 74 b8 3b 2d 0b 00 01 45 74 8b 45 74 8a 04 08 88 04 39}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_BCQ_2147799526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.BCQ!MTB"
        threat_id = "2147799526"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gennemtrkkendes" wide //weight: 1
        $x_1_2 = "BRADYPHRASIA" wide //weight: 1
        $x_1_3 = "Onomatologic3" wide //weight: 1
        $x_1_4 = "ue16hqaOSDISQAzonWSG86pg4s6aIISmEyM128" wide //weight: 1
        $x_1_5 = "Damkulturens5" wide //weight: 1
        $x_1_6 = "SJOKKEHOVEDERNES" wide //weight: 1
        $x_1_7 = "spritsmuglernes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_FC_2147805866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.FC!MTB"
        threat_id = "2147805866"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TIPOFDAY.TXT" wide //weight: 1
        $x_1_2 = "C7r7y7p7t7D7e7c7r7y7p7t7" wide //weight: 1
        $x_1_3 = "Rock Debugger" wide //weight: 1
        $x_1_4 = "PowerOfTheUniverse" ascii //weight: 1
        $x_1_5 = "nqxcsefsfscycduevs" ascii //weight: 1
        $x_1_6 = "rncmuisdncsjvme" ascii //weight: 1
        $x_1_7 = "ujnmcsasmcawe" ascii //weight: 1
        $x_1_8 = "cerummadceqwsa" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_FG_2147806249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.FG!MTB"
        threat_id = "2147806249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {15 43 00 8c 19 43 00 5c 19 43 00 1c 1b 43 00 ec 1a 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_JNK_2147807574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.JNK!MTB"
        threat_id = "2147807574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 00 04 46 01 71 01 b1 05 21 01 11 07 00 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_JNK_2147807574_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.JNK!MTB"
        threat_id = "2147807574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 56 69 65 77 4f 66 46 69 6c 65 00 04 e3 41 00 74 60 42}  //weight: 1, accuracy: High
        $x_1_2 = {00 77 00 61 00 79 00 6e 00 65 00 2d 00 62 00 72 00 61 00 75 00 6e 00 2d 00 69 00 6e 00 76 00 65}  //weight: 1, accuracy: High
        $x_1_3 = {00 2d 00 6d 00 61 00 73 00 74 00 65 00 72 00 5c 00 49 00 6e 00 76 00 65 00 73 00 74 00 73 00 2e 00 76 00 62 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_HJL_2147808923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.HJL!MTB"
        threat_id = "2147808923"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 6d 38 00 8b 34 0a ff 45 38 ff 4d 38 83 04 24 00 81 f6 e7 2d af e6 83 04 24 00 09 34 08 f8 83 34 24 00 83 e9 fc 83 04 24 00 81 f9 f8 80 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RPD_2147813207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RPD!MTB"
        threat_id = "2147813207"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 3d 5a 42 87 da 43 49 6a 3c 5b 8d 98 19 02 00 00 50 59 69 c9 01 03 00 00 6a 00 6a 01 8b 45 e4 50}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RPL_2147814099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RPL!MTB"
        threat_id = "2147814099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 00 c3 cc cc cc cc cc cc cc cc cc cc cc cc cc e9 eb ff ff ff cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_DB_2147818861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.DB!MTB"
        threat_id = "2147818861"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 ca 8a 9c 0d fc fe ff ff 32 1c 39 48 30 58 01 fe ca 4e 75 ea}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 ca 8a 9c 0d fc fe ff ff 02 1c 39 48 00 58 01 fe ca 4e 75 ea}  //weight: 1, accuracy: High
        $x_1_3 = "GetTickCount" ascii //weight: 1
        $x_1_4 = "QueryPerformanceCounter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_BA_2147824394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.BA!MTB"
        threat_id = "2147824394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 c4 08 32 1d ?? ?? ?? ?? 88 18 ff 07 81 3f 58 6c 00 00 75}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_BA_2147824394_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.BA!MTB"
        threat_id = "2147824394"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loGitech" wide //weight: 1
        $x_1_2 = "Ligestillingskonsulenterne" wide //weight: 1
        $x_1_3 = "Skrivenglers4" wide //weight: 1
        $x_1_4 = "Kontoudskriften" ascii //weight: 1
        $x_1_5 = "Unmitigatedly1" ascii //weight: 1
        $x_1_6 = "Mariengroschen7" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_S_2147829689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.S!MTB"
        threat_id = "2147829689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Exsiccatae8" wide //weight: 1
        $x_1_2 = "Unafflictedly7" wide //weight: 1
        $x_1_3 = "Pericystium7" wide //weight: 1
        $x_1_4 = "Handlingslammelserne0" ascii //weight: 1
        $x_1_5 = "Aktantmodellers" ascii //weight: 1
        $x_1_6 = "Nonperversive4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RPF_2147833576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RPF!MTB"
        threat_id = "2147833576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 01 c8 56 81 f6 [0-100] 5e 31 30 51 81 c9}  //weight: 1, accuracy: Low
        $x_1_2 = {59 39 18 0f 85 89 fe ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RPX_2147836001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RPX!MTB"
        threat_id = "2147836001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e fc 31 c9 81 c9 fc 1f 00 00 89 c7 51 f3 a4 59 81 34 08 ?? ?? ?? ?? 83 e9 04 7d f4 ff e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RPX_2147836001_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RPX!MTB"
        threat_id = "2147836001"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 07 90 90 b0 29 90 90 30 07 8a 07 90 90 90 e8}  //weight: 1, accuracy: High
        $x_1_2 = {90 90 43 81 fb 07 5d 00 00 75 b7 81 c6 34 08 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_SRP_2147836054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.SRP!MTB"
        threat_id = "2147836054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8a 04 3b 2c 0c 34 7e 2c 5a 88 04 3b 47 3b 7d f0 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RB_2147836574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RB!MTB"
        threat_id = "2147836574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 56 57 8d 3d ?? ?? ?? ?? 8b 75 08 ac 34 37 aa 3c 00 75 f8 5f 5e c9 c2 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RB_2147836574_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RB!MTB"
        threat_id = "2147836574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 10 6b c0 22 6b f6 22 89 45 fc 2b 83 48 02 00 00 83 e8 21 50}  //weight: 1, accuracy: High
        $x_1_2 = {6a 22 5b 89 45 08 8b 45 e0 99 f7 f9 8b c8 8b 45 e4 99 f7 fb 89 45 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RD_2147839420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RD!MTB"
        threat_id = "2147839420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 f9 02 00 00 06 40 12 00 00 ff 02 04 00 00 00 ff cc 31 00 1e 14 33 e1 f8}  //weight: 1, accuracy: High
        $x_1_2 = "prestigetabetpanoanniaisroughs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RPS_2147840902_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RPS!MTB"
        threat_id = "2147840902"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 07 4e 75 e3 c7 07 01 00 00 00 90 89 f6 ff 07 81 3f ?? ?? ?? ?? 75 f3 6a 04 68 00 30 00 00 68 d3 b5 00 00 6a 00 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RPY_2147841457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RPY!MTB"
        threat_id = "2147841457"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 db 90 8d 43 01 b9 93 00 00 00 33 d2 f7 f1 81 fa ff 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b c6 03 c3 88 10 89 c0 90 90 89 ff 43 81 fb 97 e7 6c 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RE_2147841632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RE!MTB"
        threat_id = "2147841632"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {b5 cc 49 51 40 af 32 76 1b 46 92 f2 cc 1a fe 6a 02 72 84}  //weight: 5, accuracy: High
        $x_1_2 = "Lnkortets.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_RN_2147843389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.RN!MTB"
        threat_id = "2147843389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 55 d4 8b 55 d4 8b 0a 03 4d e8 8b 45 d4 89 08 8b 45 08 03 45 f0 8b 10 33 55 ec 8b 45 08 03 45 f0 89 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_BK_2147852244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.BK!MTB"
        threat_id = "2147852244"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 4b 41 30 e7 2c 2b 2b 40 40 a8 7b 4d 2e 33 34 34 3a 34 8d a4 66 43 3c 59 2a 2a 2f 2f d2 36 2d 2d 2b 2c 2c 30 41 4c 68 3f 62 62 86 86 86 62 62 3f 61 4c 41 30 30 3b 45 e6}  //weight: 1, accuracy: High
        $x_1_2 = {33 33 58 5d 34 ac 80 64 2a 2a 2a 2a 2a 2a 2f 2f d2 31 2d 2b 2b 2c 30 41 4c 61 3f 62 86 5c 54 c7 54 5c 73}  //weight: 1, accuracy: High
        $x_1_3 = {69 55 5c ae c4 51 05 35 e7 35 4a 4a 35 c2 e5 6d 37 32 39 38 3e 44 2a 43 2a 66 2a 2a 36 36 40 2d 2b 2c 30 30 4c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_AFE_2147894007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.AFE!MTB"
        threat_id = "2147894007"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 33 f6 57 56 ff 15 ?? ?? ?? ?? 56 56 56 56 ff 15 ?? ?? ?? ?? 56 56 56 56}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_GNF_2147896540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.GNF!MTB"
        threat_id = "2147896540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 00 80 f6 38 02 00 07 02 00 80 74 02 00 80 ?? ?? 00 80 ?? ?? ?? ?? 1a 39 02 00 97 02 00 80 32 39 02 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_AFA_2147905635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.AFA!MTB"
        threat_id = "2147905635"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 e8 f8 1e fc ff e8 1b 1e fc ff 2b c3 3d e8 03 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {b9 5e 34 2f 1c 33 d2 8b c3 e8 ?? ?? ?? ?? 89 45 fc e8 ?? ?? ?? ?? 68 00 80 00 00 6a 00 53}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_BB_2147949975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.BB!MTB"
        threat_id = "2147949975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {83 c4 08 32 1d ?? ?? ?? ?? 88 18 89 ff 90 89 c9 89 c9 ff 07 81 3f 96 6f 00 00 75}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_BC_2147949977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.BC!MTB"
        threat_id = "2147949977"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {33 d2 8a 55 ef 33 94 85 e0 fb ff ff 88 16 ?? ?? ?? ?? 46 ff 4d e0 0f 85}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_BE_2147951028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.BE!MTB"
        threat_id = "2147951028"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {8a 08 8b c7 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 88 08}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Fareit_EOKI_2147951135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fareit.EOKI!MTB"
        threat_id = "2147951135"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fareit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 d2 8a 55 f3 33 94 85 e0 fb ff ff 88 16 90 89 d2 90 46 ff 4d e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

