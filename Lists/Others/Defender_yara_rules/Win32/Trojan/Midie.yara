rule Trojan_Win32_Midie_SIB_2147806066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIB!MTB"
        threat_id = "2147806066"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "56"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = "Control_RunDLL" ascii //weight: 50
        $x_1_2 = {8b 11 31 f6 8d bc 24 ?? ?? ?? ?? bd ?? ?? ?? ?? 89 d3 [0-10] 89 d1 c1 eb 04 b8 ?? ?? ?? ?? 80 e1 ?? 80 f9 ?? 0f 42 c5 46 00 c8 83 fa ?? 89 da 88 47 ff 8d 7f ff 77}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 11 31 ed 8d bc 24 ?? ?? ?? ?? be ?? ?? ?? ?? 89 d3 [0-16] 89 d1 c1 eb 04 b8 ?? ?? ?? ?? 80 e1 ?? 80 f9 ?? 0f 42 c6 45 00 c8 83 fa ?? 89 da 88 47 ff 8d 7f ff 77}  //weight: 1, accuracy: Low
        $x_5_4 = {64 a1 30 00 00 00 89 7c 24 ?? 8b 40 0c 8b 68 14 89 6c 24 ?? 85 ed 0f 84 ?? ?? ?? ?? 66 90 8b 75 28 33 c9 0f b7 55 24 [0-10] 0f b6 3e c1 c9 ?? 80 3e 61 72 03 83 c1 ?? 81 c2 ff ff 00 00 03 cf 46 66 85 d2 75 ?? 81 f9 ?? ?? ?? ?? 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Midie_SIBF_2147810219_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBF!MTB"
        threat_id = "2147810219"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\trapped.pdf" ascii //weight: 1
        $x_1_2 = "\\hotdog.dll" ascii //weight: 1
        $x_1_3 = {6a 40 57 8d 8d ?? ?? ?? ?? 51 ff d0 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 00 8d 4d ?? 51 57 8d 8d 00 51 50 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 00 81 f9 ?? ?? ?? ?? 74 ?? [0-5] 04 2d 34 24 [0-8] 2c 77 [0-8] 04 ea [0-5] 34 65 88 84 0d 00 83 c1 01 8a 84 0d 00 81 f9 07 b0 00 b9 00 00 00 00 8d 85 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBG_2147810220_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBG!MTB"
        threat_id = "2147810220"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\stepfather\\bowels.pdf" ascii //weight: 1
        $x_1_2 = "\\airwaves\\lemonade.bmp" ascii //weight: 1
        $x_1_3 = {b9 00 00 00 00 8a 84 0d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 74 ?? [0-5] 04 ?? [0-8] 2c af [0-5] 2c 95 88 84 0d 00 83 c1 01 8a 84 0d 00 81 f9 01 b0 00 b9 00 00 00 00 68 ?? ?? ?? ?? 68 ?? 0d ff 15 ?? 0d 50 ff 15 ?? 0d 8d 4d ?? 51 6a ?? 56 8d 8d 00 51 ff d0 8d 85 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBH_2147810221_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBH!MTB"
        threat_id = "2147810221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "jsalfhxh.dll" ascii //weight: 1
        $x_1_2 = {33 c9 85 db 74 ?? 8a 04 39 [0-10] 34 ?? [0-10] 04 ?? 34 ?? 88 04 39 41 3b cb 72 ?? 6a 00 57 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBH_2147810221_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBH!MTB"
        threat_id = "2147810221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "dcnwnqsg.pdb" ascii //weight: 1
        $x_1_2 = {6a 40 68 00 ?? 00 00 8b d8 53 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 ?? 8a 04 39 [0-32] 34 ?? [0-32] 34 ?? [0-32] 34 ?? 88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBH_2147810221_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBH!MTB"
        threat_id = "2147810221"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\compiling\\flock\\admonish.jpg" ascii //weight: 1
        $x_1_2 = "\\provides.exe" ascii //weight: 1
        $x_1_3 = {6a 40 57 8d 8d ?? ?? ?? ?? 51 ff d0 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 00 8d 4d ?? 51 57 8d 8d 00 51 50 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 00 81 f9 ?? ?? ?? ?? 74 ?? [0-5] 2c 14 34 84 [0-8] 2c e6 04 5f 34 2f 2c aa [0-8] 88 84 0d 00 83 c1 01 8a 84 0d 00 81 f9 07 b0 00 b9 00 00 00 00 8d 85 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBJ_2147810222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBJ!MTB"
        threat_id = "2147810222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "yzlhbxxh.dll" ascii //weight: 1
        $x_1_2 = {33 c9 85 db 74 ?? 8a 04 39 [0-32] 34 a2 [0-32] fe c0 34 4f [0-32] 88 04 39 41 3b cb 72 ?? 6a 00 57 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBJ_2147810222_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBJ!MTB"
        threat_id = "2147810222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\breakthrough.exe" ascii //weight: 1
        $x_1_2 = {51 56 8d 8d ?? ?? ?? ?? 51 50 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 00 81 f9 ?? ?? ?? ?? 74 ?? [0-8] 04 ?? [0-8] 34 ?? [0-5] 04 ?? 34 ?? [0-5] 88 84 0d 00 83 c1 01 8a 84 0d 00 81 f9 03 b0 00 b9 00 00 00 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8d 4d ?? 51 6a 40 56 8d 8d 00 51 ff d0 8d 85 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBK_2147810320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBK!MTB"
        threat_id = "2147810320"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\breakthrough\\integral.dll" ascii //weight: 1
        $x_1_2 = "\\disagreements.au" ascii //weight: 1
        $x_1_3 = {68 80 00 00 00 6a 03 56 6a 07 68 00 00 00 80 50 ff 15 ?? ?? ?? ?? 56 8d 4d ?? be ?? ?? ?? ?? 51 56 8d 8d ?? ?? ?? ?? 51 50 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 03 81 f9 02 74 ?? [0-8] 2c ?? [0-8] 34 ?? [0-21] 2c ?? [0-5] 04 ?? 88 84 0d 03 83 c1 01 8a 84 0d 03 81 f9 02 b0 00 b9 00 00 00 00 68 ?? ?? ?? ?? 68 ?? 16 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8d 4d ?? 51 6a 40 56 8d 8d 03 51 ff d0 8d 85 03 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBM_2147810321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBM!MTB"
        threat_id = "2147810321"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\integral\\devils.exe" ascii //weight: 1
        $x_1_2 = "\\churches\\brock.au" ascii //weight: 1
        $x_1_3 = {b9 00 00 00 00 8a 84 0d ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 74 ?? [0-8] 04 ?? [0-8] 2c ?? [0-8] 34 ?? [0-8] 88 84 0d 00 83 c1 01 8a 84 0d 00 81 f9 01 b0 00 b9 00 00 00 00 68 ?? ?? ?? ?? 68 ?? 10 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8d 4d ?? 51 6a 40 56 8d 8d 00 51 ff d0 8d 85 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBN_2147810322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBN!MTB"
        threat_id = "2147810322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\breakthrough.pdf" ascii //weight: 1
        $x_1_2 = "\\classical.lnk" ascii //weight: 1
        $x_1_3 = {6a 40 57 8d 8d ?? ?? ?? ?? 51 ff d0 6a 00 68 80 00 00 00 6a 03 6a 00 6a 07 68 00 00 00 80 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 6a 00 8d 4d ?? 51 57 8d 8d 00 51 50 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 00 81 f9 ?? ?? ?? ?? 74 ?? 2c ?? [0-8] 34 ?? [0-6] 04 ?? [0-8] 2c ?? 88 84 0d 00 83 c1 01 8a 84 0d 00 81 f9 07 b0 00 b9 00 00 00 00 8d 85 00 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBP_2147810688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBP!MTB"
        threat_id = "2147810688"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "skxlszqn.dll" ascii //weight: 1
        $x_1_2 = {52 6a 40 68 ?? ?? ?? ?? 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 01 81 f9 00 74 ?? [0-8] 04 ?? 34 ?? [0-8] 04 f7 [0-8] 88 84 0d 01 83 c1 01 8a 84 0d 01 81 f9 00 b0 00 b9 00 00 00 00 8d 8d 01 ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SINQ_2147810689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SINQ!MTB"
        threat_id = "2147810689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "qnizkqmx.dll" ascii //weight: 1
        $x_1_2 = {50 6a 40 68 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 01 81 f9 00 74 ?? [0-8] fe c8 34 ?? [0-8] 04 ?? fe c0 [0-8] 34 ?? 88 84 0d 01 83 c1 01 8a 84 0d 01 81 f9 00 b0 00 b9 00 00 00 00 8d 95 01 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBR_2147810690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBR!MTB"
        threat_id = "2147810690"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "eptowgmf.dll" ascii //weight: 1
        $x_1_2 = {50 6a 40 68 ?? ?? ?? ?? 8d 8d ?? ?? ?? ?? 51 ff 15 ?? ?? ?? ?? b9 00 00 00 00 8a 84 0d 01 81 f9 00 74 ?? [0-8] 34 ?? 04 ?? [0-5] 2c ?? [0-8] 04 ?? 34 ?? 88 84 0d 01 83 c1 01 8a 84 0d 01 81 f9 00 b0 00 b9 00 00 00 00 8d 95 01 ff d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBJ1_2147812431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBJ1!MTB"
        threat_id = "2147812431"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "vmsloanb.dll" ascii //weight: 1
        $x_1_2 = {33 c9 85 db 74 ?? 8a 04 39 [0-32] 2c ?? [0-32] 04 ?? [0-32] 88 04 39 41 3b cb 72 ?? 6a 00 57 6a 00 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBG3_2147812542_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBG3!MTB"
        threat_id = "2147812542"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 00 00 00 00 8a 81 ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 74 ?? [0-32] 34 ?? 2c ?? [0-32] 34 ?? [0-32] 04 ?? [0-32] 88 81 00 83 c1 01 8a 81 00 81 f9 01 b0 00 b9 00 00 00 00 8d 45 ?? 50 6a 40 68 01 68 00 ff 15 ?? ?? ?? ?? b9 00 ff d1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBG14_2147814067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBG14!MTB"
        threat_id = "2147814067"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<program name unknown>" wide //weight: 1
        $x_1_2 = {8b 55 08 b8 ?? ?? ?? ?? 8a 0a 84 c9 6b c0 ?? 0f be c9 03 c1 42}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 30 00 00 8b d8 53 57 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 ?? 8a 04 39 [0-10] 34 ?? [0-10] 2c ?? [0-10] 88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBG15_2147814068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBG15!MTB"
        threat_id = "2147814068"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "<program name unknown>" wide //weight: 1
        $x_1_2 = {8b 55 08 b8 ?? ?? ?? ?? 8a 0a 84 c9 6b c0 ?? 0f be c9 03 c1 42}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 40 68 00 30 00 00 8b d8 53 57 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 ?? 8a 04 39 [0-10] 34 ?? [0-10] 34 ?? [0-10] 34 ?? [0-10] 88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBH1_2147814660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBH1!MTB"
        threat_id = "2147814660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 ?? 00 00 8b d8 53 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 ?? 8a 04 39 [0-32] 34 ?? [0-32] 34 ?? [0-32] 04 ?? 88 04 39 41 3b cb 72 eb 6a 00 6a 00 57 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBH2_2147814661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBH2!MTB"
        threat_id = "2147814661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 40 68 00 ?? 00 00 8b d8 53 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 d2 85 db 74 ?? 8a 0c 3a [0-32] 80 f1 ?? [0-32] 88 04 3a 42 3b d3 72 ?? 6a 00 6a 00 57 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBH3_2147815015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBH3!MTB"
        threat_id = "2147815015"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 40 68 00 ?? 00 00 8b d8 53 6a 00 ff 15 ?? ?? ?? ?? 6a 00 8b f8 8d 45 ?? 50 53 57 56 ff 15 ?? ?? ?? ?? 33 c9 85 db 74 1a [0-16] 8a 04 39 [0-32] 04 ?? [0-32] 34 ?? [0-32] 88 04 39 41 3b cb 72 ?? 6a 00 6a 00 57 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SIBQ_2147815016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SIBQ!MTB"
        threat_id = "2147815016"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 10 04 0b 0f 28 cb 66 0f fc c8 66 0f f8 ca 66 0f f8 cc 66 0f ef cd 66 0f ef ce 66 0f ef cf 66 0f ef 0d ?? ?? ?? ?? 66 0f fc ca 66 0f fc 0d ?? ?? ?? ?? 66 0f ef 0d ?? ?? ?? ?? 66 0f f8 0d ?? ?? ?? ?? 0f 11 0c 0b 0f 10 44 0b 10 66 0f fc c3 66 0f f8 c2 66 0f f8 c4 66 0f ef c5 66 0f ef c6 66 0f ef c7 66 0f ef 05 00 66 0f fc c2 66 0f fc 05 01 66 0f ef 05 02 66 0f f8 05 03 0f 11 44 0b 10 83 c1 20 3b ca 0f 82}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_GNC_2147850660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.GNC!MTB"
        threat_id = "2147850660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0f b6 41 fd c0 c8 03 32 82 ?? ?? ?? ?? 88 41 fd 8d 42 01 99 f7 ff 0f b6 41 fe c0 c8 03 32 82 ?? ?? ?? ?? 88 41 fe 8d 42 01 99 f7 ff 83 ee}  //weight: 10, accuracy: Low
        $x_1_2 = "HvDeclY" ascii //weight: 1
        $x_1_3 = "_FileExcists@4" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_GMH_2147889382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.GMH!MTB"
        threat_id = "2147889382"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8d 64 24 00 8a 14 39 80 ea 24 80 f2 25 88 14 39 41 3b c8}  //weight: 10, accuracy: High
        $x_1_2 = "Boudle_ftp2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_GMC_2147897361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.GMC!MTB"
        threat_id = "2147897361"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 24 50 ff 15 ?? ?? ?? ?? 8b f8 85 ff 74 ?? 53 66 c7 44 24 14 02 00 ff d5 66 89 44 24 12 8b 4f 0c 6a 10 8b 11 8d 4c 24 14 51 8b 02 8b 56 08 52 89 44 24 20 ff 15}  //weight: 10, accuracy: Low
        $x_1_2 = "Ch7Demo6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_NM_2147900809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.NM!MTB"
        threat_id = "2147900809"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 a0 0f 00 00 ff 30 83 c7 ?? e8 22 17 00 00 59 59 85 c0 74 0c 46 83 fe ?? 7c d2 33 c0}  //weight: 5, accuracy: Low
        $x_1_2 = "MJPGC.TMP" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_MBFW_2147906463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.MBFW!MTB"
        threat_id = "2147906463"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 33 c0 21 45 ec 88 45 ff 40 8b 7d 08 8b f0 89 45 f4 b9 9b 83 01 00 89 45 f8 33 db}  //weight: 1, accuracy: High
        $x_1_2 = {5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 70 6f 72 74 00 6d 69 6b 79 2e 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_NB_2147909353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.NB!MTB"
        threat_id = "2147909353"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c1 e0 03 c1 eb 02 90}  //weight: 10, accuracy: High
        $x_2_2 = "_crypted.dll" ascii //weight: 2
        $x_2_3 = "MSIGame" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SPHT_2147909808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SPHT!MTB"
        threat_id = "2147909808"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 40 68 00 30 00 00 68 81 71 02 00 6a 00 ff 90}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_YZ_2147912031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.YZ!MTB"
        threat_id = "2147912031"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {88 54 24 13 8a 94 30 6c c9 43 00 2a d3 32 54 24 13 83 c0 01 3b c1 88 94 30 6b c9 43 00 7c e5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SSB_2147917734_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SSB!MTB"
        threat_id = "2147917734"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 b7 12 00 00 c6 45 fc 02 8b 45 10 50 8b 4d 0c 83 c9 02 51 8b 55 08 52 8b 4d f0 83 c1 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_MBXP_2147918352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.MBXP!MTB"
        threat_id = "2147918352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 8b ec 6a ff 68 ?? b2 65 00 68 ?? 5e 65 00 64 a1 00 00 00 00 50 64 89 25 00 00 00 00 83 ec 58 53 56 57 89 65 e8 ff 15 00 b1 65 00 33 d2 8a d4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_GNM_2147919721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.GNM!MTB"
        threat_id = "2147919721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 d8 bb 99 00 00 00 ?? 31 c3 80 07 ?? 80 2f ?? ?? 89 d8 bb ?? ?? ?? ?? ?? 31 c3 f6 2f 47 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_GNM_2147919721_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.GNM!MTB"
        threat_id = "2147919721"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 4d f8 8b 51 40 0f b7 0a 99 f7 f9 83 c2 01 89 55 fc 6a 00 8b 55 fc 69 d2 e8 03 00 00 81 c2 b8 0b 00 00 52}  //weight: 5, accuracy: High
        $x_5_2 = {6a 00 6a 04 8b 4d 08 83 c1 0c 51 8b 55 d8 52 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_VPAA_2147920355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.VPAA!MTB"
        threat_id = "2147920355"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 44 24 0c 8b 15 e4 71 00 10 03 c1 8a 14 32 30 10 46 41 3b 0f 72 e2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_WRX_2147920954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.WRX!MTB"
        threat_id = "2147920954"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {34 1e 30 1f 66 83 e8 10 66 03 ca 03 c1 66 03 44 24 ?? 66 8b c8 8b 7d fc 47 89 7d fc 8a 44 24 cc 66 33 4c 24 d4 b0 28 2a 4c 24 e0 03 4c 24 f5 83 6d f8 01 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_MKV_2147920975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.MKV!MTB"
        threat_id = "2147920975"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b c2 66 8b 44 24 c6 66 83 c1 4c 03 7d f0 88 17 66 33 d0 8b d1 66 8b 44 24 ?? 80 c1 0c 80 e9 15 34 1e 30 1f 66 83 e8 10 66 03 ca 03 c1 66 03 44 24 a0 66 8b c8 8b 7d fc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_AMX_2147925098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.AMX!MTB"
        threat_id = "2147925098"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f6 17 58 50 89 c0 35 85 00 00 00 90 80 07 63 80 2f 27 58 50 89 c0 35 85 00 00 00 90 f6 2f 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SEF_2147937991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SEF!MTB"
        threat_id = "2147937991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hox/1hirefh01 Fh1001ho/20hGeckh.0) hv:16h4; rhWOW6h.1; hNT 6hows hWindh.0 (hla/5hozilh" ascii //weight: 1
        $x_1_2 = "dummyWindowClass" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_A_2147945991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.A!MTB"
        threat_id = "2147945991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 68 06 00 02 00 6a 00 68 a0 41 00 10 68 01 00 00 80 ff 15 04 30 00 10 85 c0 75 23 51 ?? b9 a1 06 00 00 59 68 05 15 00 00 ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_KHT_2147947911_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.KHT!MTB"
        threat_id = "2147947911"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f b6 c0 89 0d ?? ?? ?? ?? 8b 4d 0c 8a 44 38 08 32 04 0a 88 01 eb ?? 8b 4d 0c 8b 75 a4 8b 7d 84 41 83 ad 78 ff ff ff 01 89 4d 0c 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_KAB_2147950797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.KAB!MTB"
        threat_id = "2147950797"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {3e 8d 0c b5 00 00 00 00 8b 0c 08 33 4d fc 3e 8d 14 b5 00 00 00 00 89 0c 10 83 c6 ?? 3b 75 0c 75}  //weight: 20, accuracy: Low
        $x_8_2 = "7yz-11.dll" ascii //weight: 8
        $x_7_3 = "C:\\aow_dr.cmd" ascii //weight: 7
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SX_2147952309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SX!MTB"
        threat_id = "2147952309"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8b 4d fc 8b 45 fc 03 c9 33 ce 46 03 c1 89 45 fc e8 ?? ?? ?? ?? 99 f7 ff 81 c2 ?? ?? ?? ?? 3b f2 7c de}  //weight: 3, accuracy: Low
        $x_2_2 = {0f 11 45 80 ff d6 0f 10 45 a0 8d 45 b0 50 0f 11 85 70 ff ff ff ff d6 0f 10 45 b0 8d 85 50 ff ff ff 50}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_AHI_2147957305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.AHI!MTB"
        threat_id = "2147957305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {8b 45 8c 89 45 d4 8b 45 d8 89 45 c4 c7 45 bc ?? ?? ?? ?? 8b 45 d4 6b c0}  //weight: 30, accuracy: Low
        $x_20_2 = {89 85 78 ff ff ff 8b 45 d4 03 45 a0 66 0f b6 08 8b 45 ?? 66 2b 08 0f}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_BA_2147957456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.BA!MTB"
        threat_id = "2147957456"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b d7 13 cf c1 ea ?? 0f a4 ef 10 33 c0 c1 e5 ?? 0b c7 0b d5 33 c1 33 54 24 ?? 33 ed 0b 6c 24 ?? 01 54 24 1c 13 e8 33 ff 89 6c 24 14}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_LMC_2147957474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.LMC!MTB"
        threat_id = "2147957474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {81 e2 00 00 00 80 09 c2 89 d1 89 c8 d1 e8 8b 14 ?? ?? ?? ?? ?? 31 d0 89 ca 83 e2 01 8b 14 95 40 04 41 00 31 c2}  //weight: 30, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_KK_2147958708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.KK!MTB"
        threat_id = "2147958708"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fm_installing_bot_1984" ascii //weight: 1
        $x_2_2 = "fm_working_bot_1984" ascii //weight: 2
        $x_3_3 = "Bot path:" ascii //weight: 3
        $x_4_4 = "down_and_run" ascii //weight: 4
        $x_5_5 = "Remote path:" ascii //weight: 5
        $x_6_6 = "OK download Bot!" ascii //weight: 6
        $x_7_7 = "OK ShellExecute Bot!" ascii //weight: 7
        $x_8_8 = "FALSE ShellExecute Bot!" ascii //weight: 8
        $x_9_9 = "FAIL download Bot! sleep" ascii //weight: 9
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Midie_SXC_2147959004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Midie.SXC!MTB"
        threat_id = "2147959004"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Midie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {c7 85 78 ff ff ff 2e 64 6c 6c 0f 28 05 ?? ?? ?? ?? c6 85 7c ff ff ff 00 0f 11 45 a0 c7 45 b0 69 74 79 50 c7 45 b4 6c 61 79 65 c7 45 b8 72 2e 64 6c 66 c7 45 bc 6c 00}  //weight: 15, accuracy: Low
        $x_10_2 = {83 c4 0c c7 85 c8 fe ff ff 00 04 00 00 8d 85 c4 fe ff ff c7 85 d0 fe ff ff ?? ?? ?? ?? c7 85 d4 fe ff ff ?? ?? ?? ?? c7 85 e0 fe ff ff ?? ?? ?? ?? 50 ff 15}  //weight: 10, accuracy: Low
        $x_1_3 = "taskkill /f /im hh.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

