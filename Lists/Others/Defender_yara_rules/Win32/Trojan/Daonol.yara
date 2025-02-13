rule Trojan_Win32_Daonol_A_132991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.A"
        threat_id = "132991"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 35 50 e8 ?? ?? ff ff 8b 44 24 10 8b 54 24 08 c6 44 10 35 2b 6a 0a e8}  //weight: 1, accuracy: Low
        $x_1_2 = {68 45 01 00 00 8b 44 24 1c 50 8b 44 24 18 50 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Daonol_D_140414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.D"
        threat_id = "140414"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "C:\\WINDOWS\\SYSTEM32\\sqlsodbc.chm" ascii //weight: 4
        $x_2_2 = "virut~" ascii //weight: 2
        $x_2_3 = "FOOBAR" ascii //weight: 2
        $x_1_4 = "miekiemoes" ascii //weight: 1
        $x_1_5 = "FooBar.local.host" ascii //weight: 1
        $x_1_6 = "local.foo.com" ascii //weight: 1
        $x_1_7 = "foobarg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Daonol_C_140417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.C"
        threat_id = "140417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "AntiMcHTNOD3LIVEPand<UA COMOESS CAUpLiveNortSpySEnigAVPUTMUFAdobSUPEMpCo" ascii //weight: 5
        $x_1_2 = "mcafee" ascii //weight: 1
        $x_1_3 = "kaspersky" ascii //weight: 1
        $x_1_4 = "symantec" ascii //weight: 1
        $x_1_5 = "onecare" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Daonol_C_140417_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.C"
        threat_id = "140417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AntiMcHTNOD3LIVEPand<UA COMOESS CAUpliveNortSpySEnigAVPUTMUFAdobSUPE" ascii //weight: 2
        $x_1_2 = {31 c9 83 c7 08 57 51 51 b5 80 51 6a 00 55 89 e8 8b 4b 54 8d 7e fb ff d7}  //weight: 1, accuracy: High
        $x_1_3 = {03 5b 3c 8b 7b 50 57 47 c1 e6 10 6a 40 99 b6 30 52 57 56 ff d5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Daonol_E_141392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.E"
        threat_id = "141392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 02 33 f6 c7 44 24 04 2e 2e 5c 00}  //weight: 1, accuracy: High
        $x_1_2 = {80 f1 d5 88 4c 02 ff 4a 75 f2}  //weight: 1, accuracy: High
        $x_1_3 = {8a 27 35 d5 d5 00 00 88 66 ff}  //weight: 1, accuracy: High
        $x_1_4 = {76 17 81 bc 24 10 0c 00 00 49 54 53 46 74 0a}  //weight: 1, accuracy: High
        $x_1_5 = {8a 0a 8a 5c 34 0c 32 cb 8d 98 62 0d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Daonol_G_145180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.G"
        threat_id = "145180"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "software\\microsoft\\windows nt\\currentversion\\drivers32" ascii //weight: 1
        $x_1_2 = "winmm.dll" ascii //weight: 1
        $x_1_3 = "AntiMcHTNOD3LIVEPand" ascii //weight: 1
        $x_1_4 = "\\internet explorer\\iexplore.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Daonol_H_145273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.H"
        threat_id = "145273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 38 47 45 54 20 74 04}  //weight: 1, accuracy: High
        $x_1_2 = "cse?t" ascii //weight: 1
        $x_1_3 = {80 a8 12 01 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Daonol_I_145289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.I"
        threat_id = "145289"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 80 38 5a 74 03 83 c2 f8 48 ff d2 [0-16] e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Daonol_J_145370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.J"
        threat_id = "145370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 00 40 80 38 5a 74 03 83 c2 f8 48 ff d2 [0-40] b8 ?? ?? ?? ?? b8 ?? ?? ?? ?? e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff e8 ?? ?? ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Daonol_A_145873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.gen!A"
        threat_id = "145873"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 18 46 00 00 ac 32 c2 80 c2 ?? (88|aa) e2}  //weight: 1, accuracy: Low
        $x_1_2 = {bd 19 46 00 00 30 9e ?? ?? ?? ?? 46 [0-2] ff d7 80 eb ?? 4d 75}  //weight: 1, accuracy: Low
        $x_1_3 = {bd 19 46 00 00 81 c6 ?? ?? ?? ?? 53 46 8a 24 24 30 24 2e 46 (ff d7|e8 ?? ?? ?? ??) 80 eb ?? 4d 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Daonol_L_145940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.L"
        threat_id = "145940"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 d2 89 10 c6 85 ?? ?? ff ff 39 8d 85 ?? ?? ff ff c7 00 6d 69 64 69 06 00 8d 85 ?? ?? ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {55 ff 53 04 ff d0 85 c0 0f 84 ?? ?? ?? ?? 56 ff 53 10 97 6a 00 6a 01 50 8b 6b 24 03 6d 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Daonol_M_148044_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.M"
        threat_id = "148044"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 8d 4d d0 [0-10] 66 4b [0-10] ff 34 37 [0-10] 33 41 fc [0-10] 46 [0-10] c1 e0 08 [0-10] 88 64 37 ff [0-10] 4f [0-10] 75}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 4d d0 66 4b [0-10] ff 34 37 [0-10] 8b 49 fc [0-10] 31 c8 [0-10] 03 0c 06 06 46 [0-10] c1 (e0|c0) 08 d3 c8 [0-10] 46 46 [0-10] d3 c8 [0-10] 88 (64|44) 37 ff [0-10] 4f [0-10] 75 [0-10] 46 [0-10] (81|83) c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Daonol_N_154047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daonol.N"
        threat_id = "154047"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daonol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {aa 8b 45 c4 ff 40 f1}  //weight: 3, accuracy: High
        $x_1_2 = {ff 74 87 d0 81 fe ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {ff 74 47 02 81 fe ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {ff 74 87 fc 81 fe ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

