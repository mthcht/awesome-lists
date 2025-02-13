rule Virus_Win32_Patchload_B_2147636673_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Patchload.gen!B"
        threat_id = "2147636673"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Patchload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hresshcAddhtProfhGe" ascii //weight: 1
        $x_1_2 = "haryAhLibrhLoad" ascii //weight: 1
        $x_1_3 = {66 6a 00 68 56 41 5f 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Patchload_I_2147640599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Patchload.I"
        threat_id = "2147640599"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Patchload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 45 f8 8b 50 08 8b 7c 02 08 3b fa 0f 87 ?? ?? ?? ?? 81 ff 38 01 00 00 0f 82 ?? ?? ?? ?? 68 34 9d 41 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 02 68 c8 9d 41 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Patchload_J_2147641400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Patchload.J"
        threat_id = "2147641400"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Patchload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff d3 85 c0 0f 85 ?? ?? ?? ?? 8b 45 f8 8b 50 08 8b 7c 02 08 3b fa 0f 87 ?? ?? ?? ?? 81 ff 38 01 00 00 0f 82 ?? ?? ?? ?? 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 75 ec}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Patchload_C_2147642384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Patchload.gen!C"
        threat_id = "2147642384"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Patchload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 78 65 63 00 68 57 69 6e 45 35 00 47 65 74 50 [0-16] 72 6f 63 41}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Virus_Win32_Patchload_D_2147642385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Patchload.gen!D"
        threat_id = "2147642385"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Patchload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 47 65 74 (50|00)}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 47 65 74 50}  //weight: 1, accuracy: High
        $x_1_3 = {b8 72 6f 63 41}  //weight: 1, accuracy: High
        $x_1_4 = {b8 4c 69 62 72}  //weight: 1, accuracy: High
        $x_1_5 = {b8 4c 6f 61 64}  //weight: 1, accuracy: High
        $x_1_6 = {b8 6f 6c 65 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Virus_Win32_Patchload_E_2147648446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Patchload.gen!E"
        threat_id = "2147648446"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Patchload"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {84 d2 0f 85 a1 00 00 00 85 c9 0f 84 c2 00 00 00 81 f9 55 c6 79 92 0f 84 b6 00 00 00 81 f9 8b b9 b5 c2 0f 84 aa 00 00 00 81 f9 b3 12 23 de 0f 84 9e 00 00 00 81 f9 57 90 1e 4f 0f 84 92 00 00 00 81 f9 0f cb 2e 90 0f 84 86 00 00 00 81 f9 07 39 ef 51 74 7e 81 f9 20 7a 1d c7 74 76 81 f9 bc 5b 0a c5 74 6e}  //weight: 1, accuracy: High
        $x_1_2 = {89 4d d4 81 f9 ?? ?? 00 00 7d 34 8b 14 8d ?? ?? 00 10 89 55 e0 8b c2 c1 e8 16 c1 e2 0a 0b c2 89 45 e0 33 c1 89 45 e0 2b c1 89 45 e0 8b d0}  //weight: 1, accuracy: Low
        $x_1_3 = {89 55 d4 81 fa ?? ?? 00 00 7d 22 8b 0c 95 ?? ?? 00 10 89 4d ?? 8b c1 c1 e0 ?? c1 e9 ?? 0b c1 89 45 ?? 2b c2 89 45 ?? 89 04 96 42 eb d3 ff d6}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 14 85 f8 db 00 10 eb ?? 8b d0 c1 e2 ?? c1 e8 ?? 0b c2 89 45 ?? 05 ?? ?? 00 00 89 45 ?? 0f b6 c9 03 c1 e9 ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

