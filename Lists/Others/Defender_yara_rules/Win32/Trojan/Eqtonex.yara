rule Trojan_Win32_Eqtonex_F_2147720969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eqtonex.F"
        threat_id = "2147720969"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eqtonex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 40 90 74 08 e8 09 00 00 00 c2 24 00 e8 a7 00 00 00 c3 e8 01 00 00 00 eb 90 5b b9 76 01 00 00 0f 32 a3 fc ff df ff 8d 43 17 31 d2 0f 30 c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 c2 48 c1 ea 20 0f 30 c3 0f 01 f8 65 48 89 24 25 10 00 00 00 65 48 8b 24 25 a8 01 00 00 50 53 51 52 56 57 55 41 50 41 51 41 52 41 53 41 54}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 48 8b 04 25 38 00 00 00 48 8b 40 04 48 c1 e8 0c 48 c1 e0 0c 48 8b 18 66 81 fb 4d 5a 74 08 48 2d 00 10 00 00 eb ee 5b c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Eqtonex_G_2147721994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eqtonex.G!dha"
        threat_id = "2147721994"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eqtonex"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 44 24 19 53}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 1a 4d}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 1b 42}  //weight: 1, accuracy: High
        $x_1_4 = {c6 44 24 18 69}  //weight: 1, accuracy: High
        $x_1_5 = {c6 44 24 19 64}  //weight: 1, accuracy: High
        $x_1_6 = {00 5c 5c 25 73 5c 49 50 43 24 00}  //weight: 1, accuracy: High
        $x_1_7 = "__TREEID__PLACEHOLDER__" ascii //weight: 1
        $x_1_8 = "__USERID__PLACEHOLDER__" ascii //weight: 1
        $x_1_9 = "__TREEPATH_REPLACE__" ascii //weight: 1
        $x_2_10 = {e8 01 00 00 00 eb 90 5b b9 76 01 00 00 0f 32 a3 fc ff df ff 8d 43 17 31 d2 0f 30 c3}  //weight: 2, accuracy: High
        $x_2_11 = {ff 35 fc ff df ff 60 9c 6a 23 52 9c 6a 02 83 c2 08 9d}  //weight: 2, accuracy: High
        $x_1_12 = {94 01 69 e3}  //weight: 1, accuracy: High
        $x_1_13 = {85 54 83 f0}  //weight: 1, accuracy: High
        $x_1_14 = {2e 5b 51 d2}  //weight: 1, accuracy: High
        $x_1_15 = {fa 3c ad c2}  //weight: 1, accuracy: High
        $x_1_16 = {1a bd 4b 2b}  //weight: 1, accuracy: High
        $x_1_17 = "h.datja" ascii //weight: 1
        $x_1_18 = {48 bf 2e 64 61 74 61 00 00 00 48 83 f9 00}  //weight: 1, accuracy: High
        $x_6_19 = {68 b8 0b 00 00 ff d6 68 bd 01 00 00 8d 44 24 0c 6a 01 50 e8 ?? ?? ?? ?? 83 c4 0c 85 c0 75 1f 68 b8 0b 00 00 ff d6 8d 4c 24 08 68 bd 01 00 00 51 e8 ?? ?? ?? ?? 83 c4 08 47 83 ff 05 7c c2}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_6_*) and 4 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Eqtonex_A_2147726376_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eqtonex.A"
        threat_id = "2147726376"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eqtonex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 c9 6d a9 33 60 ba 8f 3b 48 dd 2b d1 8b ca c1 ea 08 30 10 40}  //weight: 1, accuracy: High
        $x_1_2 = "prkMtx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Eqtonex_B_2147726377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eqtonex.B"
        threat_id = "2147726377"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eqtonex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {69 c9 0d 66 19 00 81 c1 5f f3 6e 3c 8b f1 c1 ee 10 66 81 ce 00 80 66 31 34 42 40 3b 45 10}  //weight: 2, accuracy: High
        $x_2_2 = {64 6c 6c 5f 70 00 64 6c 6c 5f 75 00}  //weight: 2, accuracy: High
        $x_1_3 = "\\??\\%s\\%s" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Eqtonex_C_2147726379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eqtonex.C"
        threat_id = "2147726379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eqtonex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 61 69 6e 57 72 61 70 70 65 72 [0-32] 5f 73 65 74 56 61 6c 69 64 61 74 65 [0-32] 5f 73 65 74 50 72 6f 63 65 73 73 [0-32] 5f 73 65 74 49 44 [0-32] 5f 64 65 6c 65 74 65 [0-32] 5f 63 72 65 61 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Eqtonex_D_2147726380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eqtonex.D"
        threat_id = "2147726380"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eqtonex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 61 69 6e 57 72 61 70 70 65 72 [0-32] 5f 73 65 74 56 61 6c 69 64 61 74 65 [0-32] 5f 73 65 74 50 72 6f 63 65 73 73 [0-32] 5f 73 65 74 49 44 [0-32] 5f 64 65 6c 65 74 65 [0-32] 5f 63 72 65 61 74 65}  //weight: 1, accuracy: Low
        $x_1_2 = "10c67c6f8ff73eb12e2f96318b878835e3513aae" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Eqtonex_E_2147726381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eqtonex.E"
        threat_id = "2147726381"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eqtonex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6d 61 69 6e 57 72 61 70 70 65 72 [0-32] 5f 73 65 74 56 61 6c 69 64 61 74 65 [0-32] 5f 73 65 74 50 72 6f 63 65 73 73 [0-32] 5f 73 65 74 49 44 [0-32] 5f 64 65 6c 65 74 65 [0-32] 5f 63 72 65 61 74 65}  //weight: 1, accuracy: Low
        $x_1_2 = "f3e5259c1024c871792e73dd9632909eb795b902" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Eqtonex_SA_2147778359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eqtonex.SA!MTB"
        threat_id = "2147778359"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eqtonex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT hostname,httpRealm,encryptedUsername,encryptedPassword FROM moz_logins;" ascii //weight: 1
        $x_1_2 = "TnRTZXRJbmZvcm1hdGlvblByb2Nlc3M" ascii //weight: 1
        $x_1_3 = "TWljcm9zb2Z0XHBlcnNpc3QuZGF0" ascii //weight: 1
        $x_1_4 = "TWljcm9zb2Z0XFNlYXJjaFw" ascii //weight: 1
        $x_1_5 = "V0VSOW1zby5kaXIwMFw" ascii //weight: 1
        $x_1_6 = "%c:\\Program Files\\%ls\\" wide //weight: 1
        $x_1_7 = "UnRsQWRqdXN0UHJpdmlsZWdl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Eqtonex_RPF_2147836273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Eqtonex.RPF!MTB"
        threat_id = "2147836273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Eqtonex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 ec 08 85 c0 75 15 8b 44 24 18 8b 54 24 14 0f b7 04 58 8b 0c 82 01 e9 89 4c 24 10 83 c3 01 39 5f 18 77 c7}  //weight: 1, accuracy: High
        $x_1_2 = {89 c2 89 c5 c1 ea 1c c1 ed 1e 83 e5 01 83 e2 02 01 ea 89 c5 c1 ed 1f 8d 54 55 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

