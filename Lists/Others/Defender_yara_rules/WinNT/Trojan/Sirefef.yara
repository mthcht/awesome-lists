rule Trojan_WinNT_Sirefef_A_142987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.A"
        threat_id = "142987"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\?\\globalroot\\Device\\__max++>\\%08X.x86.dll" wide //weight: 1
        $x_1_2 = "<head><title>search</title></head><script>location.replace(\"%s\")</script>" ascii //weight: 1
        $x_1_3 = "GET /search?q=%S HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_A_142987_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.A"
        threat_id = "142987"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 06 56 01 00 c0 5f}  //weight: 1, accuracy: High
        $x_1_2 = {8d 48 34 eb 02 33 c9 8b 44 24 08 85 c0 74 05 83 c0 34 eb 02 33 c0 6a 01 51 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {83 c3 f8 83 c7 02 ?? c7 06 03 00 00 a0 66 89 5e 04 66 89 7e 0c ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = "__max++" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_WinNT_Sirefef_A_142987_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.A"
        threat_id = "142987"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 06 56 01 00 c0 5f}  //weight: 1, accuracy: High
        $x_1_2 = {8d 48 34 eb 02 33 c9 8b 44 24 08 85 c0 74 05 83 c0 34 eb 02 33 c0 6a 01 51 50 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = {83 c3 f8 83 c7 02 ?? c7 06 03 00 00 a0 66 89 5e 04 66 89 7e 0c ff 15}  //weight: 1, accuracy: Low
        $x_1_4 = "__max++" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_WinNT_Sirefef_A_142987_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.A"
        threat_id = "142987"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\?\\globalroot\\Device\\__max++>\\%08X.x86.dll" wide //weight: 1
        $x_1_2 = "<head><title>search</title></head><script>location.replace(\"%s\")</script>" ascii //weight: 1
        $x_1_3 = "GET /search?q=%S HTTP/1.1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_B_142988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.B"
        threat_id = "142988"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ce d1 f9 8b 34 88 03 75 08 89 4d fc 6a 0f bf}  //weight: 1, accuracy: High
        $x_1_2 = {33 db 8b d3 fe c3 8a 04 33 02 d0 8a 24 32 88 24 33 02 e0 88 04 32 0f b6 c4 8a 04 30 30 07 47 e2 e3 05 00 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_B_142988_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.B"
        threat_id = "142988"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 ce d1 f9 8b 34 88 03 75 08 89 4d fc 6a 0f bf}  //weight: 1, accuracy: High
        $x_1_2 = {33 db 8b d3 fe c3 8a 04 33 02 d0 8a 24 32 88 24 33 02 e0 88 04 32 0f b6 c4 8a 04 30 30 07 47 e2 e3 05 00 b9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_A_142990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.gen!A"
        threat_id = "142990"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeGetCurrentIrql" ascii //weight: 1
        $x_1_2 = "ProbeForRead" ascii //weight: 1
        $x_1_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 45 78 57 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 45 78 57 20 3d 20 25 70}  //weight: 1, accuracy: High
        $x_1_4 = {00 64 3a 5c 76 63 35 5c 72 65 6c 65 61 73 65 5c 6b 69 6e 6a 65 63 74 2e}  //weight: 1, accuracy: High
        $x_1_5 = "delete apc %" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_A_142990_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.gen!A"
        threat_id = "142990"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeGetCurrentIrql" ascii //weight: 1
        $x_1_2 = "ProbeForRead" ascii //weight: 1
        $x_1_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 45 78 57 00 00 4c 6f 61 64 4c 69 62 72 61 72 79 45 78 57 20 3d 20 25 70}  //weight: 1, accuracy: High
        $x_1_4 = {00 64 3a 5c 76 63 35 5c 72 65 6c 65 61 73 65 5c 6b 69 6e 6a 65 63 74 2e}  //weight: 1, accuracy: High
        $x_1_5 = "delete apc %" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_B_142993_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.gen!B"
        threat_id = "142993"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeGetCurrentIrql" ascii //weight: 1
        $x_1_2 = "ProbeForRead" ascii //weight: 1
        $x_1_3 = ":\\vc5\\release\\kinject." ascii //weight: 1
        $x_1_4 = "\\\\?\\globalroot\\Device\\__max++>\\%08X.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_B_142993_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.gen!B"
        threat_id = "142993"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeGetCurrentIrql" ascii //weight: 1
        $x_1_2 = "ProbeForRead" ascii //weight: 1
        $x_1_3 = ":\\vc5\\release\\kinject." ascii //weight: 1
        $x_1_4 = "\\\\?\\globalroot\\Device\\__max++>\\%08X.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_C_147967_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.C"
        threat_id = "147967"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 40 08 25 ff ff ff 00 bb 22 00 00 c0 3d 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 7e 44 c5 a7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_C_147967_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.C"
        threat_id = "147967"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 40 08 25 ff ff ff 00 bb 22 00 00 c0 3d 00 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {68 7e 44 c5 a7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_D_148104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.D"
        threat_id = "148104"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7c 1c 6a 62 68 ?? ?? ?? ?? 6a 01 6a 00 68 ?? ?? ?? ?? ff 74 24 20 ff d6 ff 74 24 0c ff d7 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_D_148104_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.D"
        threat_id = "148104"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7c 1c 6a 62 68 ?? ?? ?? ?? 6a 01 6a 00 68 ?? ?? ?? ?? ff 74 24 20 ff d6 ff 74 24 0c ff d7 68}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_C_155383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.gen!C"
        threat_id = "155383"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0a 6b c0 ?? 80 e1 df 0f be f1 33 c6 42 84 c9 75 ee}  //weight: 1, accuracy: Low
        $x_1_2 = {49 00 44 00 45 00 5c 00 5b 00 63 00 6d 00 7a 00 20 00 76 00 6d 00 6b 00 64 00 5d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 56 01 00 c0 ff 75 fc ff 15 ?? ?? ?? ?? ff 75 fc ff 15 ?? ?? ?? ?? 8b 75 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_WinNT_Sirefef_C_155383_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.gen!C"
        threat_id = "155383"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 0a 6b c0 ?? 80 e1 df 0f be f1 33 c6 42 84 c9 75 ee}  //weight: 1, accuracy: Low
        $x_1_2 = {49 00 44 00 45 00 5c 00 5b 00 63 00 6d 00 7a 00 20 00 76 00 6d 00 6b 00 64 00 5d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 56 01 00 c0 ff 75 fc ff 15 ?? ?? ?? ?? ff 75 fc ff 15 ?? ?? ?? ?? 8b 75 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_WinNT_Sirefef_G_163871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.G"
        threat_id = "163871"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 20 89 44 24 ?? 6a 07 8d 44 24 ?? 50 8d 44 24 ?? 50 68 bf 01 12 00}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 18 6a 01 bb 9a 00 00 c0 ff 15 ?? ?? ?? ?? 85 c0 0f 84}  //weight: 2, accuracy: Low
        $x_1_3 = "\\\\.\\globalroot\\Device\\svchost.exe\\svchost.exe" wide //weight: 1
        $x_1_4 = "GenDisk" wide //weight: 1
        $x_1_5 = "IDE\\" wide //weight: 1
        $x_1_6 = "USB storage device" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Sirefef_G_163871_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.G"
        threat_id = "163871"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 20 89 44 24 ?? 6a 07 8d 44 24 ?? 50 8d 44 24 ?? 50 68 bf 01 12 00}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 18 6a 01 bb 9a 00 00 c0 ff 15 ?? ?? ?? ?? 85 c0 0f 84}  //weight: 2, accuracy: Low
        $x_1_3 = "\\\\.\\globalroot\\Device\\svchost.exe\\svchost.exe" wide //weight: 1
        $x_1_4 = "GenDisk" wide //weight: 1
        $x_1_5 = "IDE\\" wide //weight: 1
        $x_1_6 = "USB storage device" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Sirefef_I_166223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.I"
        threat_id = "166223"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0b ff 15 ?? ?? ?? ?? 8b f8 85 ff 7c 10 ff 75 0c 8d 46 04 ff 75 08 e8 ?? ?? ?? ?? 8b d8 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 ff ff 00 00 66 89 4e 38 8b 4f 24 89 4e 24 8b 4f 28 89 4e 28 8b 4f 2c 89 4e 2c 8b 4f 30 89 4e 30 0f b7 4f 2c 8b 57 28 2b d1 0f b7 4f 24 83 c4 0c ff 75 0c 03 d1 89 56 30 ff 75 08 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_I_166223_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.I"
        threat_id = "166223"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 3f 00 3f 00 5c 00 25 00 30 00 38 00 78 00 5c 00 55 00 5c 00 40 00 25 00 30 00 38 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\systemroot\\$NtUninstallKB%u$" wide //weight: 1
        $x_1_4 = "\\driver\\%I64u" wide //weight: 1
        $x_3_5 = {8b 43 3c 8b 6c 18 78 03 eb 8b 4d 18 8b 75 20 8b 55 24 03 d3 03 f3 ad 60 8d 34 03 33 ff 8b c7 b9 3f 00 01 00 0f b6 c0 03 c7 f7 e1}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Sirefef_I_166223_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.I"
        threat_id = "166223"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 0b ff 15 ?? ?? ?? ?? 8b f8 85 ff 7c 10 ff 75 0c 8d 46 04 ff 75 08 e8 ?? ?? ?? ?? 8b d8 6a 00}  //weight: 1, accuracy: Low
        $x_1_2 = {b9 ff ff 00 00 66 89 4e 38 8b 4f 24 89 4e 24 8b 4f 28 89 4e 28 8b 4f 2c 89 4e 2c 8b 4f 30 89 4e 30 0f b7 4f 2c 8b 57 28 2b d1 0f b7 4f 24 83 c4 0c ff 75 0c 03 d1 89 56 30 ff 75 08 ff d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_I_166223_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.I"
        threat_id = "166223"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 00 3f 00 3f 00 5c 00 25 00 30 00 38 00 78 00 5c 00 55 00 5c 00 40 00 25 00 30 00 38 00 78 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 72 00 6f 00 6f 00 74 00 5c 00 61 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "\\systemroot\\$NtUninstallKB%u$" wide //weight: 1
        $x_1_4 = "\\driver\\%I64u" wide //weight: 1
        $x_3_5 = {8b 43 3c 8b 6c 18 78 03 eb 8b 4d 18 8b 75 20 8b 55 24 03 d3 03 f3 ad 60 8d 34 03 33 ff 8b c7 b9 3f 00 01 00 0f b6 c0 03 c7 f7 e1}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_WinNT_Sirefef_J_167505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.J"
        threat_id = "167505"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\driver\\%I64u" wide //weight: 1
        $x_1_2 = "\\systemroot\\$NtUninstallKB%u$" wide //weight: 1
        $x_1_3 = {8b 54 24 2c 8b 4c 24 30 8b 44 24 3c 89 56 0c 8b 54 24 34 89 4e 14 89 46 10 89 56 2c a1 ?? ?? ?? ?? 8b 40 14 8b 50 2c 89 51 2c 8b 50 30 8b 7c 24 30 89 57 30 8b 50 24 89 51 24 8b 40 28 89 41 28 8b 4c 24 44 51 56 ff 54 24 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_J_167505_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.J"
        threat_id = "167505"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\driver\\%I64u" wide //weight: 1
        $x_1_2 = "\\systemroot\\$NtUninstallKB%u$" wide //weight: 1
        $x_1_3 = {8b 54 24 2c 8b 4c 24 30 8b 44 24 3c 89 56 0c 8b 54 24 34 89 4e 14 89 46 10 89 56 2c a1 ?? ?? ?? ?? 8b 40 14 8b 50 2c 89 51 2c 8b 50 30 8b 7c 24 30 89 57 30 8b 50 24 89 51 24 8b 40 28 89 41 28 8b 4c 24 44 51 56 ff 54 24 3c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_N_173466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.N"
        threat_id = "173466"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\systemroot\\$NtUninstallKB%u$" wide //weight: 1
        $x_1_2 = "eaoimnqazw" ascii //weight: 1
        $x_1_3 = {8b 7d 08 8b f0 83 e6 1f 66 0f be b6 ?? ?? ?? ?? 0f ac d0 05 66 89 34 4f c1 ea 05 8b f1 49 85 f6 75 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_WinNT_Sirefef_N_173466_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Sirefef.N"
        threat_id = "173466"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Sirefef"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\systemroot\\$NtUninstallKB%u$" wide //weight: 1
        $x_1_2 = "eaoimnqazw" ascii //weight: 1
        $x_1_3 = {8b 7d 08 8b f0 83 e6 1f 66 0f be b6 ?? ?? ?? ?? 0f ac d0 05 66 89 34 4f c1 ea 05 8b f1 49 85 f6 75 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

