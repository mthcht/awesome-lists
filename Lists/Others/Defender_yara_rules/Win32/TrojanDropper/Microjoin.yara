rule TrojanDropper_Win32_Microjoin_AC_2147567819_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Microjoin.AC"
        threat_id = "2147567819"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Microjoin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 f4 01 00 00 90 66 57 66 33 ff 66 5f 55 8b 4b 1c 84 d2 74 4f 90 66 57 66 33 ff 66 5f d0 ea 72 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Microjoin_B_2147574801_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Microjoin.gen!B"
        threat_id = "2147574801"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Microjoin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 0a 58 6a 04 59 60 57 e8 ?? ?? 00 00 95 8b 55 3c 8b 74 2a 78 8d 74 2e 18 ad 91 ad 50 ad 03 c5 92 ad 03 c5 50 8b f2 ad 03 c5 33 d2 c1 c2 03 32 10 40 80 38 00}  //weight: 10, accuracy: Low
        $x_1_2 = {b9 2c ff e6 7a 2a c6 38 1a bb 75 14 bb f1 af 8a 95 dc 29 b9 09 ad 59 12 09 d0 f6 c2 45 c5 d8 58 7b 2a 46 49 1b 3f f4 60 71 52 9f 78 6a 9d eb 06 9a 56 4e d2 38 d9 18 a7}  //weight: 1, accuracy: High
        $x_1_3 = {bf ef 10 80 7c 00 15 f7 bf f0 13 f7 bf 70 3c f7 bf 20 3d f7 bf 20 3f f7 bf a0 3f f7 bf 40 2e f7 bf 70 2d f7 bf 70 14 f7 bf 90 1c f7 bf a2 16 45 77 e0 33 f7 bf b0 17 f7 bf 60 15 f4 77 f3 13 f4}  //weight: 1, accuracy: High
        $x_1_4 = {8b 73 68 ff 53 54 eb 13 ff 53 20 eb 0e ff 53 14 eb 09 8b ?? ?? 58 5a 50 52 ff d1 80 7d 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Microjoin_M_2147602730_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Microjoin.M"
        threat_id = "2147602730"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Microjoin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 c2 03 32 10 40 80 38 00 75 f5 8b 04 24 83 04 24 02 8b fb 39 17 75 13 0f b7 00 c1 e0 02 03 44 ?? ?? 03 c5 8b 00 03 c5 ab eb 01 af 83 3f 00 75 e3 e2}  //weight: 1, accuracy: Low
        $x_2_2 = {c6 85 00 04 00 00 00 be dd cc bb aa 68 dd cc bb aa 51 ff 53 24 89 43 60 83 ee 04 8b 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Microjoin_D_2147627357_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Microjoin.gen!D"
        threat_id = "2147627357"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Microjoin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 f4 01 00 00 90 [0-4] 55 8b 4b 1c 84 d2 74 ?? [0-4] d0 ea 72 ?? [0-4] d0 ea 72 ?? [0-4] d0 ea 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Microjoin_E_2147642799_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Microjoin.gen!E"
        threat_id = "2147642799"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Microjoin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {89 3d 00 14 40 00 8a c0 8a c0 83 c7 04 89 3d fc 13 40 00 90 8b 35 00 14 40 00 8b 0e 86 ff 86 ff 03 f9 89 3d 04 14 40 00 8a c0 8a c0 68 08 14 40 00 68 00 01 00 00}  //weight: 5, accuracy: High
        $x_4_2 = {a3 f4 13 40 00 8b 0e 8a c0 8a c0 a1 fc 13 40 00 c0 4c 01 ff 04 e2 f9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Microjoin_C_2147803979_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Microjoin.gen!C"
        threat_id = "2147803979"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Microjoin"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {56 68 f4 01 00 00 ?? 8b ?? ?? 84 d2 74 ?? d0 ea 72 ?? d0 ea 72 ?? d0 ea 72 ?? 5a ?? 8b}  //weight: 2, accuracy: Low
        $x_1_2 = {b0 5c f2 ae 51 c6 47 ff 00 6a 00 ?? ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

