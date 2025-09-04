rule Trojan_Win32_Simda_B_2147632782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.gen!B"
        threat_id = "2147632782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {80 3e 21 89 74 24}  //weight: 2, accuracy: High
        $x_2_2 = {76 0b 80 34 30 ?? 83 c0 01 3b c7 72 f5}  //weight: 2, accuracy: Low
        $x_1_3 = "/knock.php?" ascii //weight: 1
        $x_1_4 = "!config" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Simda_C_2147633716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.gen!C"
        threat_id = "2147633716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 02 35 a0 00 00 00 8b 8d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01 eb}  //weight: 2, accuracy: Low
        $x_1_2 = {0f be 02 83 f8 21 74 05}  //weight: 1, accuracy: High
        $x_1_3 = "/knock.php?" ascii //weight: 1
        $x_1_4 = "!config" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Simda_D_2147636663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.gen!D"
        threat_id = "2147636663"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 30 30 77 [0-31] 8b e3 8b eb 81 ec 00 01 00 00 51 50 fb ff d7}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 44 24 10 fb c6 44 24 11 6a 88 5c 24 12 c6 44 24 13 6a 88 5c 24 14 c6 44 24 15 e8}  //weight: 1, accuracy: High
        $x_1_3 = {3b c6 75 22 68 4e 57 50 53 ff 75 f0 ff 15}  //weight: 1, accuracy: High
        $x_1_4 = {c6 45 ec b8 c6 45 ed 4c 88 5d ee c6 45 ef cd c6 45 f0 21}  //weight: 1, accuracy: High
        $x_1_5 = {0f b7 46 06 83 c7 28 ff 45 fc 39 45 fc 7c 9e 33 ff 8d 45 f4 50 8b 46 50 03 45 f8 68 00 a0 00 00}  //weight: 1, accuracy: High
        $x_1_6 = {59 f7 f1 8b 4d 08 8a 44 15 ?? 88 04 0e 46 83 fe ?? 7c ae}  //weight: 1, accuracy: Low
        $x_1_7 = {74 0b 68 56 41 54 4e ff 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 03 ff 15 ?? ?? ?? ?? 85 c0 74 07 68 43 4d 44 56 eb e2}  //weight: 1, accuracy: Low
        $x_1_8 = {b8 4c 00 cd c6 45 ?? 21}  //weight: 1, accuracy: Low
        $x_1_9 = {8b 45 fc 3d 40 1a cd 00 74 ?? 3d 08 c5 bb 6c 74 ?? 3d 82 16 4e 77 74 ?? 3d 3e 87 7f 83 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Simda_E_2147636982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.gen!E"
        threat_id = "2147636982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "\\globalroot\\systemroot\\system32\\" ascii //weight: 2
        $x_2_2 = "AvIpcConnect" ascii //weight: 2
        $x_2_3 = "____AVP.Root" ascii //weight: 2
        $x_2_4 = "avguard01" ascii //weight: 2
        $x_2_5 = "drivers\\avgtdix.sys" ascii //weight: 2
        $x_2_6 = "AVGTRAY.EXE" ascii //weight: 2
        $x_2_7 = "\\\\.\\KmxAgent" ascii //weight: 2
        $x_1_8 = "CreateRemoteThread" ascii //weight: 1
        $x_1_9 = "CreateToolhelp32Snapshot" ascii //weight: 1
        $x_1_10 = "OpenProcess" ascii //weight: 1
        $x_1_11 = {66 81 38 4d 5a 75 18 8b 48 3c 03 c8 81 39 50 45 00 00 75 0b 8b 49 50 51 50 ff 15}  //weight: 1, accuracy: High
        $x_2_12 = {71 77 65 72 [0-4] 71 77 65 72 74 [0-4] 71 77 65 72 74 79}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 4 of ($x_1_*))) or
            ((6 of ($x_2_*) and 2 of ($x_1_*))) or
            ((7 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Simda_R_2147650743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.R"
        threat_id = "2147650743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 50 01 32 10 41 66 0f b6 c2 66 89}  //weight: 1, accuracy: High
        $x_1_2 = {8b 4c 24 08 c6 40 18 f3 89 48 20}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Simda_S_2147650744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.S"
        threat_id = "2147650744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 43 3c 03 c3 0f b7 48 14 8d 54 01 18 0f b7 40 06 8b 4a 14 03 4a 10}  //weight: 1, accuracy: High
        $x_1_2 = {83 63 58 00 b8 00 20 00 00 66 09 43 16}  //weight: 1, accuracy: High
        $x_1_3 = "wv=%s&uid=%d&lng=%s&mid=%s&res=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Simda_W_2147656567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.W"
        threat_id = "2147656567"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 55 00 53 00 45 00 52 00 5c 00 4d 00 69 00 73 00 20 00 64 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 6f 00 73 00 5c 00 44 00 65 00 73 00 63 00 61 00 72 00 67 00 61 00 73 00 5c 00 76 00 4f 00 6c 00 6b 00 2d 00 42 00 6f 00 74 00 6e 00 65 00 74 00 20 00 [0-2] 2e 00 30 00 5c 00 76 00 62 00 36 00 20 00 53 00 6f 00 75 00 72 00 63 00 65 00 5c 00 50 00 72 00 6f 00 79 00 65 00 63 00 74 00 6f 00 31 00 2e 00 76 00 62 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {52 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 54 00 65 00 78 00 74 00 00 00 00 00 0e 00 00 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {69 44 6f 6e 77 45 78 65 63 00 00 00 69 53 74 61 72 50 63 4f 6e 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Simda_RK_2147836568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.RK!MTB"
        threat_id = "2147836568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be 35 24 00 00 6b d6 59 0b 15 ?? ?? ?? ?? 75 05 c1 c2 07 d1 e2 89 15 b7 82 48 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Simda_EC_2147850520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.EC!MTB"
        threat_id = "2147850520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WumoJose" ascii //weight: 1
        $x_1_2 = "EnumResourceNamesW" ascii //weight: 1
        $x_1_3 = "GunaSyseCufyFa" ascii //weight: 1
        $x_1_4 = "Nexefoqy" ascii //weight: 1
        $x_1_5 = "Dwghzfb.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Simda_ASM_2147922891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.ASM!MTB"
        threat_id = "2147922891"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 be 00 03 3c 00 81 c6 3f 87 05 00 56 bb a3 23 12 00 8b d3 c7 05 ?? ?? ?? ?? e4 63 2f 00 03 15 ?? ?? ?? ?? 52 b9 ae 00 00 00 8b d1 52 68 00 00 00 00 5a 52 bf 88 70 20 00 8b c7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Simda_SOK_2147923707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.SOK!MTB"
        threat_id = "2147923707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 15 bc 20 41 00 33 c0 a3 ?? ?? ?? 00 ba 41 0c 00 00 c1 ea 06 03 d3 4a 8b c2 40 81 e8 f0 04 00 00 2b ?? ?? ?? 40 00 c1 c0 07 03 c0 29 05 ?? ?? ?? 00 68 1f a2 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Simda_CCIO_2147924541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.CCIO!MTB"
        threat_id = "2147924541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "heL32" ascii //weight: 1
        $x_1_2 = "hKerN" ascii //weight: 1
        $x_1_3 = "hlloc" ascii //weight: 1
        $x_1_4 = "hualA" ascii //weight: 1
        $x_1_5 = "hVirt" ascii //weight: 1
        $x_5_6 = {66 bb 10 0e 2c 1d ba 9e 00 00 00 8d 8f c0 00 00 00 33 cd}  //weight: 5, accuracy: High
        $x_5_7 = {33 ca 8f 05 61 2a 41 00 89 55 f4 aa 33 db}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Simda_MX_2147928075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.MX!MTB"
        threat_id = "2147928075"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b da d1 e3 ff 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Simda_AB_2147951436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.AB!MTB"
        threat_id = "2147951436"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 87 c6 03 ee 4e 45 83 cd 17 4e 03 eb 48 43 03 fb 4f 48 2b f8 66 09 f6 8b ca 03 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Simda_AC_2147951437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Simda.AC!MTB"
        threat_id = "2147951437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 ee 01 00 00 00 81 c7 01 00 00 00 81 eb 01 00 00 00 8b d7 43 8b c2 29 05 78 86 41 00 48 03 05 43 85 41 00 d1 c8 48 d1 c0 2b c6 8b d0 81 ea}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

