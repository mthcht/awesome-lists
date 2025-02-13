rule BrowserModifier_Win32_Webalta_169511_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Webalta"
        threat_id = "169511"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Webalta"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Global\\SearchService" ascii //weight: 1
        $x_1_2 = "WebaltaService" ascii //weight: 1
        $x_1_3 = "P$ro$cess" ascii //weight: 1
        $x_1_4 = "D$own$load" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Webalta_169511_1
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Webalta"
        threat_id = "169511"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Webalta"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b1 2e 83 f8 04 7e 0b 38 4c 18 fc 75 05 c6 44 18 fc 00 83 f8 05 7e 0b 38 4c 18 fb 75 05 c6 44 18 fb 00 83 f8 08 7e 0b 38 4c 18 f9 75 05 c6 44 18 f9 00 83 f8 09}  //weight: 1, accuracy: High
        $x_1_2 = "Global\\SearchService" ascii //weight: 1
        $x_1_3 = "WebaltaService" ascii //weight: 1
        $x_1_4 = "webalta.ru/srch" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule BrowserModifier_Win32_Webalta_169511_2
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Webalta"
        threat_id = "169511"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Webalta"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 55 f0 32 45 e3 88 44 1a ff 47 4e 75 e0 3b 5d ec 7c c8 8b 55 f0 8b 4d ec 8b 45 f4 e8}  //weight: 5, accuracy: High
        $x_1_2 = {57 65 62 d0 b0 6c 74 d0 b0 2e 72 75 07 43 68 65 63 6b 65 64 09}  //weight: 1, accuracy: High
        $x_1_3 = {2f 67 65 74 5f 63 68 65 61 74 73 6d 61 6e 69 61 5f 6c 69 6e 6b 2e 70 68 70 3f 6c 6f 61 64 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {32 71 33 34 63 72 33 71 34 77 72 74 33 65 35 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 74 6f 72 72 e5 6e 74 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 5f 72 61 72}  //weight: 1, accuracy: Low
        $x_1_6 = {71 6d 00 00 74 78 74 00 55 8b ec}  //weight: 1, accuracy: High
        $x_1_7 = {2f 70 61 72 74 6e 65 72 3d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Webalta_169511_3
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Webalta"
        threat_id = "169511"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Webalta"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {85 c0 7e 17 ba 01 00 00 00 8b 4d ?? 8a 4c 11 ff 8b 75 ?? 30 0c 1e 43 42 48 75 ee 3b 5d ?? 7c d8}  //weight: 2, accuracy: Low
        $x_2_2 = {85 c0 7e 1f ba 01 00 00 00 8b 4d ?? 8a 4c 11 ff 88 4d ?? 8b 4d ?? 8d 34 19 8a 4d ?? 30 0e 43 42 48 75 e6 3b 5d ?? 7c d0}  //weight: 2, accuracy: Low
        $x_5_3 = {57 65 62 61 6c 74 61 2e 72 75 07 43 68 65 63 6b 65 64 09}  //weight: 5, accuracy: High
        $x_1_4 = {30 5f 30 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_5 = {26 7c 00 00 ff ff ff ff [0-33] 00 00 00 73 6f 66 74 00}  //weight: 1, accuracy: Low
        $x_1_6 = {68 74 74 70 3a 2f 2f [0-1] 2e 2e 2e 00}  //weight: 1, accuracy: Low
        $x_1_7 = {54 46 6f 72 6d 31 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30 41 3f 30 3a 3e 32 3a 30}  //weight: 1, accuracy: Low
        $x_5_8 = {57 65 62 d0 b0 6c 74 d0 b0 2e 72 75 07 43 68 65 63 6b 65 64 09}  //weight: 5, accuracy: High
        $x_1_9 = "/s=1 /partner=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Webalta_169511_4
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Webalta"
        threat_id = "169511"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Webalta"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/get_cheatsmania_link.php?" ascii //weight: 2
        $x_1_2 = {00 20 2f 70 61 72 74 6e 65 72 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 2f 70 61 72 74 6e 65 72 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 2f 73 3d 31 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 5f 72 61 72 00}  //weight: 1, accuracy: High
        $x_1_6 = {20 57 65 62 d0 b0 6c 74 d0 b0 2e 72 75}  //weight: 1, accuracy: High
        $x_1_7 = {54 46 6f 72 6d 31 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 30 41 3f 30 3a 3e 32 3a 30}  //weight: 1, accuracy: Low
        $x_1_8 = {57 65 62 d0 b0 6c 74 d0 b0 2e 72 75 07 43 68 65 63 6b 65 64 09}  //weight: 1, accuracy: High
        $x_1_9 = {59 de c0 d6 14 de d3 d6 df c4 56 d5 d8 c6 14 df}  //weight: 1, accuracy: High
        $x_1_10 = "Web0lt0.ru" ascii //weight: 1
        $x_1_11 = {71 6d 00 00 74 78 74 00 55 8b ec}  //weight: 1, accuracy: High
        $x_2_12 = {c7 45 ec 01 00 00 00 43 8b 45 e4 8b 55 ec 8a 44 10 ff 8b 55 f0 30 44 1a ff ff 45 ec 4e 75 e8 3b 5d e8 7c ce}  //weight: 2, accuracy: High
        $x_2_13 = {be 01 00 00 00 8b 55 e8 0f b6 7c 32 ff 8b 55 f0 8a 14 1a 8b cf 32 d1 8b 4d f0 88 14 19 43 46 48 75 e3}  //weight: 2, accuracy: High
        $x_1_14 = {2f 70 61 72 00 [0-11] 74 6e 65 72 3d 00}  //weight: 1, accuracy: Low
        $x_1_15 = {71 6d 00 00 54 58 54 00}  //weight: 1, accuracy: High
        $x_1_16 = {71 6d 00 00 6d 74 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

