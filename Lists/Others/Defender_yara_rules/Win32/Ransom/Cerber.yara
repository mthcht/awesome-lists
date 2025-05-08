rule Ransom_Win32_Cerber_A_2147709768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.A"
        threat_id = "2147709768"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CryptEncrypt" ascii //weight: 1
        $x_1_2 = "CryptImportPublicKeyInfo" ascii //weight: 1
        $x_3_3 = "Keysize: %d, Encryption time: %d" wide //weight: 3
        $x_2_4 = "Total files found: %d, Files crypted: %d" wide //weight: 2
        $x_2_5 = {63 65 72 62 65 72 00}  //weight: 2, accuracy: High
        $x_3_6 = {33 d2 f7 f7 50 ff 35 ?? ?? ?? ?? 8d [0-5] 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 83 c4 18 6a 40}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_A_2147709768_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.A"
        threat_id = "2147709768"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {63 65 72 62 65 72 00}  //weight: 5, accuracy: High
        $x_1_2 = "cryptimportpublickeyinfo" ascii //weight: 1
        $x_1_3 = "cryptencrypt" ascii //weight: 1
        $x_2_4 = {0f b6 f0 83 fe 66 7f 30 74 25 83 fe 26 74 17 83 fe 2e 74 12 83 fe 36 74 0d 83 fe 3e 74 08 83 c6 9c 83 fe 01}  //weight: 2, accuracy: High
        $x_2_5 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8}  //weight: 2, accuracy: High
        $x_2_6 = "\"servers\":{\"statistics\":{\"data_finish\":\"{MD5_KEY}\"" ascii //weight: 2
        $x_3_7 = "{MD5_KEY}{PARTNER_ID}{OS}{IS_X64}{IS_ADMIN}{COUNT_FILES}{STOP_REASON}" ascii //weight: 3
        $x_1_8 = "1.  http://{TOR}.{SITE_1}/{PC_ID}" ascii //weight: 1
        $x_2_9 = {56 68 05 30 00 00 6a 04 ff 15 ?? ?? ?? ?? 6a 04 57 56 ff 15 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 6a 4f 68 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $n_2_10 = "Local private.key file found" ascii //weight: -2
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_A_2147711713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.A!!Cerber.gen!A"
        threat_id = "2147711713"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "Cerber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {63 65 72 62 65 72 00}  //weight: 5, accuracy: High
        $x_1_2 = "cryptimportpublickeyinfo" ascii //weight: 1
        $x_1_3 = "cryptencrypt" ascii //weight: 1
        $x_2_4 = {0f b6 f0 83 fe 66 7f 30 74 25 83 fe 26 74 17 83 fe 2e 74 12 83 fe 36 74 0d 83 fe 3e 74 08 83 c6 9c 83 fe 01}  //weight: 2, accuracy: High
        $x_2_5 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_A_2147711713_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.A!!Cerber.gen!A"
        threat_id = "2147711713"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "Cerber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Keysize: %d, Encryption time: %d" ascii //weight: 2
        $x_2_2 = "Total files found: %d, Files crypted: %d" ascii //weight: 2
        $x_2_3 = "{\"vendors\":[\"VirusBlokAda\",\"Malwarebytes\"]}" ascii //weight: 2
        $x_1_4 = {63 65 72 62 65 72 00}  //weight: 1, accuracy: High
        $x_2_5 = {c7 06 63 72 62 72}  //weight: 2, accuracy: High
        $x_1_6 = {ff 75 08 c6 45 ?? b8 66 c7 45 ?? 50 b8 89 ?? e3 66 c7 45 ?? ff d0 c6 45 ?? c3 ff d6}  //weight: 1, accuracy: Low
        $x_2_7 = {8b 4c 24 04 c7 00 6e 6f 73 6a 89 48 14 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_A_2147711713_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.A!!Cerber.gen!A"
        threat_id = "2147711713"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "Cerber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encrypting done. Time left: %dms" ascii //weight: 1
        $x_1_2 = "Network searching done. Time left: %dms" ascii //weight: 1
        $x_1_3 = "CryptImportKey failed, GetLastError == %x" ascii //weight: 1
        $x_2_4 = {c7 03 44 72 62 52 66 89 43 15}  //weight: 2, accuracy: High
        $x_1_5 = {b8 42 4d 00 00 53 66 89 45 a0}  //weight: 1, accuracy: High
        $x_1_6 = {c7 45 d8 08 02 00 00 c7 45 dc 01 68 00 00 89 75 e0}  //weight: 1, accuracy: High
        $x_1_7 = {c7 06 06 02 00 00 c7 46 04 00 a4 00 00 c7 46 08 52 53 41 31}  //weight: 1, accuracy: High
        $x_1_8 = {b8 ba ba ba ab 39 46 04 75 11}  //weight: 1, accuracy: High
        $x_1_9 = {f6 45 08 08 b9 ba ba ba ab 89 30 89 48 04 89 4c 30 08}  //weight: 1, accuracy: High
        $x_1_10 = {8d 46 f8 8b 10 50 b9 ef be ad de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_A_2147711713_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.A!!Cerber.gen!A"
        threat_id = "2147711713"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "Cerber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MSCTF.Shared.MUTEX.%08x" ascii //weight: 1
        $x_2_2 = "CERBER_KEY_PLACE" ascii //weight: 2
        $x_2_3 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" ascii //weight: 2
        $x_1_4 = "Printers\\Defaults\\%s" ascii //weight: 1
        $x_1_5 = "Component_00" ascii //weight: 1
        $x_3_6 = "{MD5_KEY}{PARTNER_ID}{OS}{IS_X64}{IS_ADMIN}{COUNT_FILES}{STOP_REASON}" ascii //weight: 3
        $x_1_7 = "/{PC_ID}" ascii //weight: 1
        $x_2_8 = "SAPI.Speak \\\"Your documents, photos, databases and other important files have been encrypted!\\\"" ascii //weight: 2
        $x_2_9 = "\"file_extension\":\".vbs\"}],\"files_name\":" ascii //weight: 2
        $x_2_10 = "\"servers\":{\"statistics\":{\"data_finish\":\"{MD5_KEY}\"" ascii //weight: 2
        $x_1_11 = "\"# DECRYPT MY FILES #\"" ascii //weight: 1
        $x_1_12 = "ipinfo.io/json" ascii //weight: 1
        $x_1_13 = "freegeoip.net/json" ascii //weight: 1
        $x_1_14 = "ip-api.com/json" ascii //weight: 1
        $x_2_15 = {c7 03 44 72 62 52 66 89 43 0f ff 15 ?? ?? ?? ?? 8d 44 00 02 66 89 43 06}  //weight: 2, accuracy: Low
        $x_2_16 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8}  //weight: 2, accuracy: High
        $x_1_17 = "CERBER_EVALUATED_CORE_PROTECTION_EVENT" ascii //weight: 1
        $x_1_18 = "\"sqlwriter.exe\",\"oracle.exe\",\"ocssd.exe\",\"dbsnmp.exe\",\"synctime.exe\"" ascii //weight: 1
        $x_1_19 = "cerber_debug.txt" ascii //weight: 1
        $x_1_20 = "CERBER_CORE_PROTECTION_MUTEX" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_B_2147712038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.B"
        threat_id = "2147712038"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "CERBER_KEY_PLACE" wide //weight: 1
        $x_1_2 = {46 00 72 00 7a 00 5f 00 53 00 74 00 61 00 74 00 65 00 [0-8] 43 00 3a 00 5c 00 70 00 6f 00 70 00 75 00 70 00 6b 00 69 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 [0-8] 43 00 3a 00 5c 00 73 00 74 00 69 00 6d 00 75 00 6c 00 61 00 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 6f 00 6f 00 6b 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 [0-8] 6d 00 75 00 6c 00 74 00 69 00 5f 00 70 00 6f 00 74 00 2e 00 65 00 78 00 65 00 [0-8] 56 00 45 00 4e 00 5f 00 25 00 78 00}  //weight: 1, accuracy: Low
        $x_1_4 = {66 69 6c 65 5f 65 78 74 65 6e 73 69 6f 6e [0-8] 66 69 6c 65 5f 62 6f 64 79 [0-8] 2e 76 62 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_B_2147712038_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.B"
        threat_id = "2147712038"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff ff b8 8b 85 ?? ?? ff ff 89 85 ?? ?? ff ff c6 85 ?? ?? ff ff 50 c6 85 ?? ?? ff ff b8 8b 85 ?? ?? ff ff 03 45 ?? 89 85 ?? ?? ff ff c6 85 ?? ?? ff ff ff c6 85 ?? ?? ff ff d0 c6 85 ?? ?? ff ff c3 8d 85 ?? ?? ff ff 50 6a 0e 8d 85 ?? ?? ff ff 50 ff b5 ?? ?? ff ff ff 75 08 ff 15}  //weight: 3, accuracy: Low
        $x_2_2 = "CERBER_CORE_PROTECTION_MUTEX" wide //weight: 2
        $x_2_3 = "F:\\trash\\code\\work\\cerber\\bin\\Debug\\cerber_x86.pdb" ascii //weight: 2
        $x_1_4 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6e 00 67 00 20 00 66 00 69 00 6c 00 65 00 20 00 25 00 73 00 2e 00 2e 00 2e 00 0d 00 0a 00 4d 00 6f 00 64 00 69 00 66 00 69 00 65 00 64 00 20 00 61 00 74 00 20 00 25 00 73 00 20 00 25 00 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {25 00 73 00 5c 00 76 00 73 00 73 00 61 00 64 00 6d 00 69 00 6e 00 2e 00 65 00 78 00 65 00 00 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_B_2147712279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.B!!Cerber.gen!A"
        threat_id = "2147712279"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "Cerber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cerber" ascii //weight: 1
        $x_1_2 = "crbr" ascii //weight: 1
        $x_2_3 = {ff 75 08 c6 45 ?? b8 66 c7 45 ?? 50 b8 89 ?? ?? 66 c7 45 ?? ff d0 c6 45 ?? c3 ff}  //weight: 2, accuracy: Low
        $x_1_4 = {8b 4c 24 04 c7 ?? 6e 6f 73 6a 89 48 14 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {b8 94 88 01 00}  //weight: 1, accuracy: High
        $x_1_6 = {83 fe 02 72 ?? 83 fe 03 76 05 83 fe 06 75 ?? 68 08 02 00 00}  //weight: 1, accuracy: Low
        $x_2_7 = {3d 08 c5 bb 6c 74 ?? 3d 82 16 4e 77 74 ?? 3d 3e 87 7f 83 74 ?? 3d bc 64 6f 8b}  //weight: 2, accuracy: Low
        $x_1_8 = "=Q-Rs" ascii //weight: 1
        $x_1_9 = {84 c0 74 0a 81 ?? 6e 6f 73 6a 75 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_B_2147712279_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.B!!Cerber.gen!A"
        threat_id = "2147712279"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "Cerber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "{TOR}.{SITE_1}/{PC_ID}" ascii //weight: 4
        $x_2_2 = "SAPI.Speak \"Attention! Attention! Attention!\"" ascii //weight: 2
        $x_1_3 = "amdeu5.win" ascii //weight: 1
        $x_1_4 = "werti4.win" ascii //weight: 1
        $x_1_5 = "fgfid6.win" ascii //weight: 1
        $x_1_6 = "sdfiso.win" ascii //weight: 1
        $x_1_7 = "sims6n.win" ascii //weight: 1
        $x_2_8 = "SAPI.Speak \"Your docum\"+\"ents, photos, databases and other im\"+\"portant files have been encrypted!\"" ascii //weight: 2
        $x_2_9 = "on the site you will be offered to download Tor Browser;" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_B_2147712279_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.B!!Cerber.gen!A"
        threat_id = "2147712279"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "Cerber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%02x%02x%02x%02x%02x%02x%05xcerber" ascii //weight: 1
        $x_1_2 = "%[^/]%[/]%d" ascii //weight: 1
        $x_1_3 = "%c%c%c%c-%c%c%c%c-%c%c%c%c-%c%c%c%c-%c%c%c%c" ascii //weight: 1
        $x_1_4 = "%s\\vssadmin.exe" ascii //weight: 1
        $x_1_5 = "%s\\wbem\\wmic.exe" ascii //weight: 1
        $x_1_6 = "/d /c start \"\" \"%s\"" ascii //weight: 1
        $x_1_7 = "/d /c taskkill /t /f /im \"%s\"" ascii //weight: 1
        $x_1_8 = "bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_9 = "recoveryenabled no" ascii //weight: 1
        $x_1_10 = "\\StringFileInfo\\%04x%04x\\%s" ascii //weight: 1
        $x_1_11 = {00 6b 6e 6f 63 6b 00}  //weight: 1, accuracy: High
        $x_3_12 = "cerber_debug.txt" ascii //weight: 3
        $x_3_13 = "CERBER_BODY_PLACE" ascii //weight: 3
        $x_3_14 = "CERBER_CORE_PROTECTION_MUTEX" ascii //weight: 3
        $x_3_15 = "CERBER_EVALUATED_CORE_PROTECTION_EVENT" ascii //weight: 3
        $x_3_16 = "CERBER_KEY_PLACE" ascii //weight: 3
        $x_1_17 = "Component_0" ascii //weight: 1
        $x_1_18 = "delete shadows /all /quiet" ascii //weight: 1
        $x_1_19 = "Encrypting file %s..." ascii //weight: 1
        $x_1_20 = "file_body" ascii //weight: 1
        $x_1_21 = "files_name" ascii //weight: 1
        $x_1_22 = "global_public_key" ascii //weight: 1
        $x_1_23 = "help_files" ascii //weight: 1
        $x_1_24 = "min_file_size" ascii //weight: 1
        $x_1_25 = "Modified at %s %s" ascii //weight: 1
        $x_1_26 = "new_extension" ascii //weight: 1
        $x_1_27 = "Printers\\Defaults\\%s" ascii //weight: 1
        $x_1_28 = "rsa_key_size" ascii //weight: 1
        $x_1_29 = "Sending stat %s, %s" ascii //weight: 1
        $x_1_30 = "shadowcopy delete" ascii //weight: 1
        $x_1_31 = "shell.%s" ascii //weight: 1
        $x_1_32 = "site_%d" ascii //weight: 1
        $x_1_33 = "Stop reason: %s" ascii //weight: 1
        $x_1_34 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" ascii //weight: 1
        $x_1_35 = "{COUNT_FILES}" ascii //weight: 1
        $x_1_36 = "{IS_ADMIN}" ascii //weight: 1
        $x_1_37 = "{MD5_KEY}" ascii //weight: 1
        $x_1_38 = "{PARTNER_ID}" ascii //weight: 1
        $x_1_39 = "{PC_ID}" ascii //weight: 1
        $x_1_40 = "{STOP_REASON}" ascii //weight: 1
        $x_1_41 = "{TOR}" ascii //weight: 1
        $x_1_42 = "~!@#$%^&*+=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((2 of ($x_3_*) and 4 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            ((4 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_D_2147716869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.D"
        threat_id = "2147716869"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CERBER_KEY_PLACE" ascii //weight: 1
        $x_1_2 = "(in your case \\\"Cerber Decryptor\\\" software) for safe and complete" ascii //weight: 1
        $x_1_3 = "1.  http://{TOR}.{SITE_1}/{PC_ID}" ascii //weight: 1
        $x_1_4 = "<h3>C E R B E R&nbsp;&nbsp;&nbsp;R A N S O M W A R E</h3>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Cerber_E_2147717192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.E"
        threat_id = "2147717192"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c7 03 43 72 62 52}  //weight: 10, accuracy: High
        $x_10_2 = "JJJJKRJJJJOLJJJJJJJJUE@JJJEYMFJ]JJJJJJJJJJJJJJacgNJJkmJJEmJJDEJJ" ascii //weight: 10
        $x_10_3 = "@@@@AI@@@@LB@@@@@@@@ODS@@@DWC\\@" ascii //weight: 10
        $x_10_4 = "NtQueryVirtualMemory" ascii //weight: 10
        $x_10_5 = "CryptDecodeObjectEx" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_F_2147718559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.F"
        threat_id = "2147718559"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6b c9 0d d3 f8 8b 4c 24 04 d3 e0 a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? 99 c3}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 03 44 72 62 52 66 89 43 0f ff 15 ?? ?? ?? ?? 8d 44 00 02 66 89 43 06}  //weight: 1, accuracy: Low
        $x_1_3 = {75 02 0f 31 8b 15 ?? ?? ?? ?? 6b f6 64 8b c8 c1 e1 0b 33 c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_G_2147719300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.G"
        threat_id = "2147719300"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8}  //weight: 1, accuracy: High
        $x_1_2 = {75 02 0f 31 8b 15 ?? ?? ?? ?? 6b f6 64 8b c8 c1 e1 0b 33 c8}  //weight: 1, accuracy: Low
        $x_1_3 = {33 c0 6a 0f ff 35 38 43 43 00 66 89 43 04 66 a1 e0 42 43 00 c7 03 44 72 62 52 66 89 43 15 ff 15}  //weight: 1, accuracy: High
        $n_1_4 = "Local private.key file found" ascii //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_H_2147719345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.H"
        threat_id = "2147719345"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encrypting done. Time left: %dms" ascii //weight: 1
        $x_1_2 = "Network searching done. Time left: %dms" ascii //weight: 1
        $x_1_3 = "CryptImportKey failed, GetLastError == %x" ascii //weight: 1
        $x_2_4 = {c7 03 44 72 62 52 66 89 43 15}  //weight: 2, accuracy: High
        $x_1_5 = {b8 42 4d 00 00 53 66 89 45 a0}  //weight: 1, accuracy: High
        $x_1_6 = {c7 45 d8 08 02 00 00 c7 45 dc 01 68 00 00 89 75 e0}  //weight: 1, accuracy: High
        $x_1_7 = {c7 06 06 02 00 00 c7 46 04 00 a4 00 00 c7 46 08 52 53 41 31}  //weight: 1, accuracy: High
        $x_1_8 = {b8 ba ba ba ab 39 46 04 75 11}  //weight: 1, accuracy: High
        $x_1_9 = {f6 45 08 08 b9 ba ba ba ab 89 30 89 48 04 89 4c 30 08}  //weight: 1, accuracy: High
        $x_1_10 = {8d 46 f8 8b 10 50 b9 ef be ad de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_I_2147720568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.I"
        threat_id = "2147720568"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 01 68 40 e8 7d 2c ?? e8}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 05 48 81 c4 00 01 00 00 e8 00 00 00 00 c7 44 24 04 23 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_J_2147720613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.J"
        threat_id = "2147720613"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 06 45 72 62 52}  //weight: 2, accuracy: High
        $x_1_2 = {b8 42 4d 00 00 53 66 89 45}  //weight: 1, accuracy: High
        $x_1_3 = {3d 58 0d e1 6c}  //weight: 1, accuracy: High
        $x_1_4 = {3d 81 c2 80 cd}  //weight: 1, accuracy: High
        $x_1_5 = {3d 25 bd ef ef}  //weight: 1, accuracy: High
        $x_1_6 = {74 0a 81 3e 6e 6f 73 6a 75 02}  //weight: 1, accuracy: High
        $x_2_7 = {8b 4c 24 04 c7 00 6e 6f 73 6a 89 48 14}  //weight: 2, accuracy: High
        $x_1_8 = {08 02 00 00 c7 45 ?? 01 68 00 00}  //weight: 1, accuracy: Low
        $x_1_9 = {c7 06 06 02 00 00 c7 46 04 00 a4 00 00 c7 46 08 52 53 41 31}  //weight: 1, accuracy: High
        $x_1_10 = {83 fe 02 72 ?? 83 fe 03 76 ?? 83 fe 06 75 ?? 68 08 02 00 00}  //weight: 1, accuracy: Low
        $x_1_11 = {81 7d f8 00 00 00 01 0f 85 ce 00 00 00 f6 45 f4 cc 74 ?? ?? ?? e4 66 ?? ?? 4d 5a}  //weight: 1, accuracy: Low
        $x_1_12 = {69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8 69 c9 35 ae b2 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_J_2147720613_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.J"
        threat_id = "2147720613"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CERBER RANSOMWARE" ascii //weight: 1
        $x_1_2 = "(*_READ_THIS_FILE_*)" ascii //weight: 1
        $x_1_3 = "{IS_ADMIN}" ascii //weight: 1
        $x_1_4 = "{PARTNER_ID}" ascii //weight: 1
        $x_1_5 = "{STOP_REASON}" ascii //weight: 1
        $x_1_6 = "{COUNT_FILES}" ascii //weight: 1
        $x_1_7 = "rsa_key_size" ascii //weight: 1
        $x_1_8 = "min_file_size" ascii //weight: 1
        $x_1_9 = "threads_per_core" ascii //weight: 1
        $x_1_10 = "%02X%02X%02X%02X%02X%02X" ascii //weight: 1
        $x_1_11 = "Sending stat %s, %s" ascii //weight: 1
        $x_1_12 = "YOUR DOCUMENTS, PHOTOS, DATABASES AND OTHER IMPORTANT FILES HAVE BEEN ENCRYPTED!" ascii //weight: 1
        $x_1_13 = "url('data:image/gif;base64,R0lGOD" ascii //weight: 1
        $x_1_14 = "<h1>C&#069;&#82;BE&#82; &#82;ANSOMWA&#82;&#069;</h1>" ascii //weight: 1
        $x_1_15 = "(blackList.indexOf(macAddress)" ascii //weight: 1
        $x_1_16 = "updUrl(\"en\");" ascii //weight: 1
        $x_1_17 = "PHRpdGxlPkMmIzA2OTsmIzgyO0JFJiM4Mg" ascii //weight: 1
        $x_1_18 = "server10(address, callback)" ascii //weight: 1
        $x_1_19 = "server20(address, callback)" ascii //weight: 1
        $x_1_20 = "server30(address, callback)" ascii //weight: 1
        $x_1_21 = "server40(address, callback)" ascii //weight: 1
        $x_1_22 = "changeLanguage1()" ascii //weight: 1
        $x_1_23 = "changeUrl_(address)" ascii //weight: 1
        $x_1_24 = "updUrl(language)" ascii //weight: 1
        $x_1_25 = "showBlock(language)" ascii //weight: 1
        $x_1_26 = "(\"en, ar, zh, nl, fr, de, it, ja, ko, pl, pt, es, tr\".indexOf(nav_lang)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Ransom_Win32_Cerber_J_2147720614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.J!!Cerber.gen!A"
        threat_id = "2147720614"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "Cerber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 06 45 72 62 52}  //weight: 2, accuracy: High
        $x_1_2 = {b8 42 4d 00 00 53 66 89 45}  //weight: 1, accuracy: High
        $x_1_3 = {3d 58 0d e1 6c}  //weight: 1, accuracy: High
        $x_1_4 = {3d 81 c2 80 cd}  //weight: 1, accuracy: High
        $x_1_5 = {3d 25 bd ef ef}  //weight: 1, accuracy: High
        $x_1_6 = {74 0a 81 3e 6e 6f 73 6a 75 02}  //weight: 1, accuracy: High
        $x_2_7 = {8b 4c 24 04 c7 00 6e 6f 73 6a 89 48 14}  //weight: 2, accuracy: High
        $x_1_8 = {08 02 00 00 c7 45 ?? 01 68 00 00}  //weight: 1, accuracy: Low
        $x_1_9 = {c7 06 06 02 00 00 c7 46 04 00 a4 00 00 c7 46 08 52 53 41 31}  //weight: 1, accuracy: High
        $x_1_10 = {83 fe 02 72 ?? 83 fe 03 76 ?? 83 fe 06 75 ?? 68 08 02 00 00}  //weight: 1, accuracy: Low
        $x_1_11 = {81 7d f8 00 00 00 01 0f 85 ce 00 00 00 f6 45 f4 cc 74 ?? ?? ?? e4 66 ?? ?? 4d 5a}  //weight: 1, accuracy: Low
        $x_1_12 = {69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8 69 c9 35 ae b2 c2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_J_2147720614_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.J!!Cerber.gen!A"
        threat_id = "2147720614"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "Cerber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CERBER RANSOMWARE" ascii //weight: 1
        $x_1_2 = "(*_READ_THIS_FILE_*)" ascii //weight: 1
        $x_1_3 = "{IS_ADMIN}" ascii //weight: 1
        $x_1_4 = "{PARTNER_ID}" ascii //weight: 1
        $x_1_5 = "{STOP_REASON}" ascii //weight: 1
        $x_1_6 = "{COUNT_FILES}" ascii //weight: 1
        $x_1_7 = "rsa_key_size" ascii //weight: 1
        $x_1_8 = "min_file_size" ascii //weight: 1
        $x_1_9 = "threads_per_core" ascii //weight: 1
        $x_1_10 = "%02X%02X%02X%02X%02X%02X" ascii //weight: 1
        $x_1_11 = "Sending stat %s, %s" ascii //weight: 1
        $x_1_12 = "YOUR DOCUMENTS, PHOTOS, DATABASES AND OTHER IMPORTANT FILES HAVE BEEN ENCRYPTED!" ascii //weight: 1
        $x_1_13 = "url('data:image/gif;base64,R0lGOD" ascii //weight: 1
        $x_1_14 = "<h1>C&#069;&#82;BE&#82; &#82;ANSOMWA&#82;&#069;</h1>" ascii //weight: 1
        $x_1_15 = "(blackList.indexOf(macAddress)" ascii //weight: 1
        $x_1_16 = "updUrl(\"en\");" ascii //weight: 1
        $x_1_17 = "PHRpdGxlPkMmIzA2OTsmIzgyO0JFJiM4Mg" ascii //weight: 1
        $x_1_18 = "server10(address, callback)" ascii //weight: 1
        $x_1_19 = "server20(address, callback)" ascii //weight: 1
        $x_1_20 = "server30(address, callback)" ascii //weight: 1
        $x_1_21 = "server40(address, callback)" ascii //weight: 1
        $x_1_22 = "changeLanguage1()" ascii //weight: 1
        $x_1_23 = "changeUrl_(address)" ascii //weight: 1
        $x_1_24 = "updUrl(language)" ascii //weight: 1
        $x_1_25 = "showBlock(language)" ascii //weight: 1
        $x_1_26 = "(\"en, ar, zh, nl, fr, de, it, ja, ko, pl, pt, es, tr\".indexOf(nav_lang)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Ransom_Win32_Cerber_K_2147721638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.K"
        threat_id = "2147721638"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 06 46 72 62 52}  //weight: 2, accuracy: High
        $x_1_2 = {74 0d 8b 4c 24 04 c7 00 6e 6f 73 6a 89 48 14 c3}  //weight: 1, accuracy: High
        $x_1_3 = {83 45 fc 02 e9 ?? ff ff ff 8d 88 ?? ?? ff ff 3b cb 77 ?? 80 7e 01 5c 0f 85 ?? 00 00 00 80 7e 02 75}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4e 20 83 66 20 00 89 4e 1c 80 38 3a 0f 85 ?? ?? 00 00 40 ff 0f 0f 84}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 6b 58 6a 65 66 89 45}  //weight: 1, accuracy: High
        $x_2_6 = {6a 48 6a 5a 56 89 45 ?? ff 15 ?? ?? ?? ?? 50 68 6f c4 3a 35}  //weight: 2, accuracy: Low
        $x_2_7 = {8a 45 ff ff 75 10 88 46 08 8b 45 f0 89 46 09 66 a1 ?? ?? ?? ?? 66 89 46 0f ff 15 ?? ?? ?? ?? ff 75 ec 03 c0 8b d7 66 89 46 06 66 89 5e 0d}  //weight: 2, accuracy: Low
        $x_1_8 = {38 5d fe 74 12 ff 75 f8 ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 0f 95 45 fe 8b 75 f8}  //weight: 1, accuracy: Low
        $x_2_9 = {7f 0f 8b 45 ?? 3b 05 ?? ?? ?? ?? 0f 82 ?? ?? 00 00 6a 0f 6a 0b 5b eb 0e}  //weight: 2, accuracy: Low
        $x_1_10 = "YOUR DOCUMENTS, PHOT0S, DATABASES AND OTHER IMPORTANT FILES HAVE BEEN ENCRYPTED!" ascii //weight: 1
        $x_1_11 = "If you cannot find any (*_READ_THIS_FILE_*) file at your PC, follow the instructions below:" ascii //weight: 1
        $x_1_12 = "The only way to decrypt your files is to receive" ascii //weight: 1
        $x_1_13 = "%02X%02X%02X%02X%02X%02X%05X%03X" ascii //weight: 1
        $x_1_14 = "%c%c%c%c-%c%c%c%c-%c%c%c%c-%c%c%c%c-%c%c%c%c" ascii //weight: 1
        $x_1_15 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" ascii //weight: 1
        $x_1_16 = "CERBER_CORE_PROTECTION_MUTEX" ascii //weight: 1
        $x_1_17 = "%s\\*.lnk" ascii //weight: 1
        $x_1_18 = "{RAND}" ascii //weight: 1
        $x_1_19 = "{BCHN}" ascii //weight: 1
        $x_1_20 = "{IL_1}" ascii //weight: 1
        $x_1_21 = "{IL_2}" ascii //weight: 1
        $x_1_22 = "{STOP_REASON}" ascii //weight: 1
        $x_1_23 = "{COUNT_FILES}" ascii //weight: 1
        $x_1_24 = "{PARTNER_ID}" ascii //weight: 1
        $x_1_25 = "%[^/]%[/]%d" ascii //weight: 1
        $x_1_26 = "{IS_ADMIN}" ascii //weight: 1
        $x_1_27 = "rsa_key_size" ascii //weight: 1
        $x_1_28 = "\\cerber_debug.txt" ascii //weight: 1
        $x_1_29 = "data len: %d, overlay: %s" ascii //weight: 1
        $x_1_30 = "_R_E_A_D___T_H_I_S___{RAND}_" ascii //weight: 1
        $x_1_31 = "//{TOR}.onion/{PC_ID}" ascii //weight: 1
        $x_1_32 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K" ascii //weight: 1
        $x_2_33 = "e01ENV9LRVl9e1BBUlRORVJfSUR9e09TfXtJU19YNjR9e0lTX0FETUlOfXtDT1VOVF9GSUxFU317U1RPUF9SRUFTT059e1NUQVRVU30=" ascii //weight: 2
        $x_2_34 = "PCFET0NUWVBFIGh0bWw+DQo8aHRtbCBsYW5nPSJlbiI+DQo8aGVhZD4NCgk8bWV0YSBjaGFyc2V0PSJ1dGYtOCI+DQoJPHRpdGxlP" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_K_2147721639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.K!!Cerber.gen!A"
        threat_id = "2147721639"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "Cerber: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c7 06 46 72 62 52}  //weight: 2, accuracy: High
        $x_1_2 = {74 0d 8b 4c 24 04 c7 00 6e 6f 73 6a 89 48 14 c3}  //weight: 1, accuracy: High
        $x_1_3 = {83 45 fc 02 e9 ?? ff ff ff 8d 88 ?? ?? ff ff 3b cb 77 ?? 80 7e 01 5c 0f 85 ?? 00 00 00 80 7e 02 75}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 4e 20 83 66 20 00 89 4e 1c 80 38 3a 0f 85 ?? ?? 00 00 40 ff 0f 0f 84}  //weight: 1, accuracy: Low
        $x_1_5 = {6a 6b 58 6a 65 66 89 45}  //weight: 1, accuracy: High
        $x_2_6 = {6a 48 6a 5a 56 89 45 ?? ff 15 ?? ?? ?? ?? 50 68 6f c4 3a 35}  //weight: 2, accuracy: Low
        $x_2_7 = {8a 45 ff ff 75 10 88 46 08 8b 45 f0 89 46 09 66 a1 ?? ?? ?? ?? 66 89 46 0f ff 15 ?? ?? ?? ?? ff 75 ec 03 c0 8b d7 66 89 46 06 66 89 5e 0d}  //weight: 2, accuracy: Low
        $x_1_8 = {38 5d fe 74 12 ff 75 f8 ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 0f 95 45 fe 8b 75 f8}  //weight: 1, accuracy: Low
        $x_2_9 = {7f 0f 8b 45 ?? 3b 05 ?? ?? ?? ?? 0f 82 ?? ?? 00 00 6a 0f 6a 0b 5b eb 0e}  //weight: 2, accuracy: Low
        $x_1_10 = "YOUR DOCUMENTS, PHOT0S, DATABASES AND OTHER IMPORTANT FILES HAVE BEEN ENCRYPTED!" ascii //weight: 1
        $x_1_11 = "If you cannot find any (*_READ_THIS_FILE_*) file at your PC, follow the instructions below:" ascii //weight: 1
        $x_1_12 = "The only way to decrypt your files is to receive" ascii //weight: 1
        $x_1_13 = "%02X%02X%02X%02X%02X%02X%05X%03X" ascii //weight: 1
        $x_1_14 = "%c%c%c%c-%c%c%c%c-%c%c%c%c-%c%c%c%c-%c%c%c%c" ascii //weight: 1
        $x_1_15 = "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}" ascii //weight: 1
        $x_1_16 = "CERBER_CORE_PROTECTION_MUTEX" ascii //weight: 1
        $x_1_17 = "%s\\*.lnk" ascii //weight: 1
        $x_1_18 = "{RAND}" ascii //weight: 1
        $x_1_19 = "{BCHN}" ascii //weight: 1
        $x_1_20 = "{IL_1}" ascii //weight: 1
        $x_1_21 = "{IL_2}" ascii //weight: 1
        $x_1_22 = "{STOP_REASON}" ascii //weight: 1
        $x_1_23 = "{COUNT_FILES}" ascii //weight: 1
        $x_1_24 = "{PARTNER_ID}" ascii //weight: 1
        $x_1_25 = "%[^/]%[/]%d" ascii //weight: 1
        $x_1_26 = "{IS_ADMIN}" ascii //weight: 1
        $x_1_27 = "rsa_key_size" ascii //weight: 1
        $x_1_28 = "\\cerber_debug.txt" ascii //weight: 1
        $x_1_29 = "data len: %d, overlay: %s" ascii //weight: 1
        $x_1_30 = "_R_E_A_D___T_H_I_S___{RAND}_" ascii //weight: 1
        $x_1_31 = "//{TOR}.onion/{PC_ID}" ascii //weight: 1
        $x_1_32 = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0K" ascii //weight: 1
        $x_2_33 = "e01ENV9LRVl9e1BBUlRORVJfSUR9e09TfXtJU19YNjR9e0lTX0FETUlOfXtDT1VOVF9GSUxFU317U1RPUF9SRUFTT059e1NUQVRVU30=" ascii //weight: 2
        $x_2_34 = "PCFET0NUWVBFIGh0bWw+DQo8aHRtbCBsYW5nPSJlbiI+DQo8aGVhZD4NCgk8bWV0YSBjaGFyc2V0PSJ1dGYtOCI+DQoJPHRpdGxlP" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Cerber_L_2147722430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.L!bit"
        threat_id = "2147722430"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 17 69 d2 ?? ?? ?? ?? c1 c2 ?? 69 d2 ?? ?? ?? ?? 33 da c1 c3 ?? 6b db ?? 83 c7 ?? 81 c3 ?? ?? ?? ?? 3b 7d ?? 72 d9}  //weight: 1, accuracy: Low
        $x_1_2 = {0f b6 07 c1 e0 ?? c1 e9 ?? 4a 0b c8 47 46 83 fe ?? 75 1f 69 c9 ?? ?? ?? ?? c1 c1 ?? 69 c9 ?? ?? ?? ?? 33 d9 c1 c3 ?? 6b db ?? 81 c3 ?? ?? ?? ?? 33 f6 85 d2 75}  //weight: 1, accuracy: Low
        $x_1_3 = {2b ca c1 e1 ?? d3 e8 69 c0 ?? ?? ?? ?? c1 c0 ?? 69 c0 ?? ?? ?? ?? 33 f0 33 74 24 ?? 8b c6 c1 e8 ?? 33 c6 69 c0 ?? ?? ?? ?? 8b c8 c1 e9 ?? 33 c8 69 c9 ?? ?? ?? ?? 8b c1 c1 e8 ?? 33 c1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_O_2147722798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.O!bit"
        threat_id = "2147722798"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 0c 50 68 b5 af b3 69 6a 08 68 ?? ?? ?? 00 e8 ?? ?? ?? ff 83 c4 0c 50 ff 15 ?? ?? ?? 00 50 ff 15 ?? ?? ?? 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 d7 a3 a4 2a 6a 0c 68 ?? ?? ?? 00 e8 ?? ?? ?? 00 83 c4 0c 50 68 ?? ?? ?? 00 ff 15 ?? ?? ?? 00 83 c4 0c 68 a5 de a6 b4 6a 18 68 ?? ?? ?? 00 e8 ?? ?? ?? 00 83 c4 0c 50 e8 ?? ?? ?? ff 59 68 c0 18 5a fc 6a 05 68 ?? ?? ?? 00 e8 ?? ?? ?? 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_2147766250_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber!ibt"
        threat_id = "2147766250"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Ratlin.SVMf" ascii //weight: 1
        $x_1_2 = "FukkXMEn" ascii //weight: 1
        $x_1_3 = "RMtPMq.LBMfhFukkXMEn" ascii //weight: 1
        $x_1_4 = "HreFtfFimCA" ascii //weight: 1
        $x_1_5 = {be 10 15 01 10 8d bc 24 34 01 00 00 8b 2d ?? ?? ?? ?? f3 a5 66 8b 0d ?? ?? ?? ?? 33 c0 a4 8b 3d ?? ?? ?? ?? 89 84 24 49 01 00 00 23 cf 89 84 24 4d 01 00 00 66 85 c9 0f 85 ba 00 00 00 8a 0d ?? ?? ?? ?? 8b c5 d3 f8 85 c0 0f 85 a8 00 00 00 8a 0d ?? ?? ?? ?? c0 f9 44 66 0f be c1 66 3b 05 08 12 01 10 0f 8e 8e 00 00 00 0f be 0d 9d 13 01 10 0f be d2 d1 e1 83 f2 2a 3b ca 7e 39 0f be 05 ?? ?? ?? ?? 8a 0d da 10 01 10 d3 e0 0f bf 0d ?? ?? ?? ?? c1 e1 bd 3b c8 7d 1c a0 96 10 01 10 8a 0d ?? ?? ?? ?? 8a d0 d2 fa 66 0f be ca 66 89 0d ?? ?? ?? ?? eb 47}  //weight: 1, accuracy: Low
        $x_1_6 = {8a d0 80 ca 7a 66 0f be ca 66 39 0d ?? ?? ?? ?? 7c 30 0f bf 15 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? c1 e2 a7 83 c9 27 3b d1 7d 19 a0 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 32 c1 a2 96 10 01 10 eb 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_Cerber_ACB_2147850637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.ACB!MTB"
        threat_id = "2147850637"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b d8 3b f2 74 ?? 33 c0 39 55 ?? 76 ?? 0f b6 3c 32 8b c8 c1 e1 03 d3 e7 33 df 42 40 83 e0 03 3b 55}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_YAA_2147904414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.YAA!MTB"
        threat_id = "2147904414"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 85 ec fb ff ff 03 45 f8 0f b6 08 0f b6 95 f2 fb ff ff 33 ca 8b 85 ec fb ff ff 03 45 f8 88 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_YAB_2147905900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.YAB!MTB"
        threat_id = "2147905900"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 84 95 d8 fb ff ff 88 85 ?? ?? ?? ?? 8b 4d 08 03 4d dc 0f b6 11 0f b6 85 93 fb ff ff 33 d0 8b 4d 08 03 4d dc 88 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_YAC_2147913547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.YAC!MTB"
        threat_id = "2147913547"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 55 9c 8b 45 9c 69 c0 30 09 00 00 89 45 9c 8b 4d f8 33 4d f0 83 c1 02 89 4d f8 8b 55 9c 81 ea 30 09 00 00 89 55 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_PAFY_2147927900_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.PAFY!MTB"
        threat_id = "2147927900"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6b c0 00 85 c0 74 ?? b6 56 8a d0 8a d0 0f ac ea 2a 4e 4e 0f c0 f2 0f be f4 0f b3 ce eb}  //weight: 2, accuracy: Low
        $x_2_2 = {0f be f4 0f bd f1 84 e5 80 ee 11 b2 9a 2a f4 8a f4 80 ca d2 0f c0 f2 b6 56 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_YAD_2147932627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.YAD!MTB"
        threat_id = "2147932627"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 55 b4 8b 45 dc 23 05 ?? ?? ?? ?? 33 c9 29 15 ?? ?? ?? ?? 8b 4d fc 31 55 d8 47 89 15}  //weight: 1, accuracy: Low
        $x_10_2 = {33 3d 60 96 40 00 03 3d 18 96 40 00 8b 55 08 f7 1d ?? ?? ?? ?? 03 f3 8b 45 0c 89 4d ec 8b 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Cerber_ARA_2147940934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Cerber.ARA!MTB"
        threat_id = "2147940934"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Cerber"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 14 8a 0c 0a 03 d8 a1 6c 06 44 00 32 cb 83 e8 01 88 4c 24 13 75 21}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

