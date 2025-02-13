rule Ransom_Win32_Exxroute_A_2147711007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Exxroute.A"
        threat_id = "2147711007"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Exxroute"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 57 41 4c 4c 45 54 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 63 72 79 70 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 65 5f 63 72 79 70 74 5f 72 65 61 64 6d 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "!!! Specially for your PC was generated personal RSA4096 Key , both public and private." ascii //weight: 1
        $x_1_5 = " So , there are two ways you can choose: wait for a miracle and get your price doubled, or start obtaining BITCOIN NOW!" ascii //weight: 1
        $x_2_6 = {5c 43 72 79 70 74 50 72 6f 6a 65 63 74 58 58 58 5c 4c 6f 61 64 65 72 5c 44 44 65 74 6f 75 72 73 2e 70 61 73 00}  //weight: 2, accuracy: High
        $x_2_7 = {5c 43 72 79 70 74 50 72 6f 6a 65 63 74 58 58 58 5c 4c 6f 61 64 65 72 5c 49 6e 73 74 44 65 63 6f 64 65 2e 70 61 73 00}  //weight: 2, accuracy: High
        $x_1_8 = {3a 34 34 33 20 48 54 54 50 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Exxroute_A_2147711012_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Exxroute.A!!Exxroute.gen!A"
        threat_id = "2147711012"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Exxroute"
        severity = "Critical"
        info = "Exxroute: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5f 57 41 4c 4c 45 54 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 63 72 79 70 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {64 65 5f 63 72 79 70 74 5f 72 65 61 64 6d 65 00}  //weight: 1, accuracy: High
        $x_1_4 = "!!! Specially for your PC was generated personal RSA4096 Key , both public and private." ascii //weight: 1
        $x_1_5 = " So , there are two ways you can choose: wait for a miracle and get your price doubled, or start obtaining BITCOIN NOW!" ascii //weight: 1
        $x_2_6 = {5c 43 72 79 70 74 50 72 6f 6a 65 63 74 58 58 58 5c 4c 6f 61 64 65 72 5c 44 44 65 74 6f 75 72 73 2e 70 61 73 00}  //weight: 2, accuracy: High
        $x_2_7 = {5c 43 72 79 70 74 50 72 6f 6a 65 63 74 58 58 58 5c 4c 6f 61 64 65 72 5c 49 6e 73 74 44 65 63 6f 64 65 2e 70 61 73 00}  //weight: 2, accuracy: High
        $x_1_8 = {3a 34 34 33 20 48 54 54 50 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Exxroute_B_2147711607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Exxroute.B"
        threat_id = "2147711607"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Exxroute"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 66 20 65 78 69 73 74 20 22 25 73 22 20 47 6f 74 6f 20 31 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 65 20 73 75 72 65 20 74 6f 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 53 31 31 01 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 58 53 31 00}  //weight: 1, accuracy: High
        $x_1_5 = {23 44 4f 4d 41 49 4e 23 00}  //weight: 1, accuracy: High
        $x_1_6 = {23 49 44 23 00}  //weight: 1, accuracy: High
        $x_2_7 = {8b 55 f0 8b 4d f8 8b 5d f0 0f b6 4c 19 ff 33 4d fc 88 4c 10 ff ff 45 f0 ff 4d ec 75 db 8b 45 f4 8b 55 f8 e8}  //weight: 2, accuracy: High
        $x_1_8 = {53 79 73 74 65 6d 33 32 5c 76 73 73 61 64 6d 69 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_9 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 51 75 69 65 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Exxroute_B_2147711973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Exxroute.B!!Exxroute.gen!B"
        threat_id = "2147711973"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Exxroute"
        severity = "Critical"
        info = "Exxroute: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MCrypt" ascii //weight: 1
        $x_1_2 = "MConnect" ascii //weight: 1
        $x_1_3 = "MemDll" ascii //weight: 1
        $x_1_4 = "mdd5" ascii //weight: 1
        $x_1_5 = {79 13 df 2c 01 df 6c 01 08 df 7c 11 08 df 3c 11 83 c1 10 78 ed df 2c 01 df 3c 11 8b 44 01 08 89 44 11 08}  //weight: 1, accuracy: High
        $x_2_6 = {00 d0 00 76 0b eb 02 7e 07 ?? 00 00 d0 00 eb 03}  //weight: 2, accuracy: Low
        $x_2_7 = {74 31 81 bd ?? ?? ff ff e8 03 00 00 75 4a}  //weight: 2, accuracy: Low
        $x_2_8 = {8b 45 d8 8b 40 04 50 8b 45 ec 50 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? c7 85 ?? ?? ff ff e8 03 00 00}  //weight: 2, accuracy: Low
        $x_2_9 = {75 0f 81 7d ?? 18 01 00 00 0f 86 ?? ?? ?? ?? eb 06 0f 8e ?? ?? ?? ?? 6a 00 6a 00 8b 45 ?? 8b 55 ?? 2d 18 01 00 00 83 da 00}  //weight: 2, accuracy: Low
        $x_2_10 = {68 18 01 00 00 8d 85 ?? ?? ff ff 50 8b 45 ?? 50 e8 ?? ?? ?? ?? 83 f8 01 1b c0 40 84 c0 75 10 c7 45 ?? 08 00 00 00 eb 07 c7 45 ?? 09 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Exxroute_B_2147711973_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Exxroute.B!!Exxroute.gen!B"
        threat_id = "2147711973"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Exxroute"
        severity = "Critical"
        info = "Exxroute: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "If exist \"%s\" Goto " ascii //weight: 1
        $x_1_2 = "Be sure" ascii //weight: 1
        $x_1_3 = {4d 53 31 31 01 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {23 44 4f 4d 41 49 4e 23 00}  //weight: 1, accuracy: High
        $x_1_5 = {23 49 44 23 00}  //weight: 1, accuracy: High
        $x_2_6 = {8b 55 f0 8b 4d f8 8b 5d f0 0f b6 4c 19 ff 33 4d fc 88 4c 10 ff ff 45 f0 ff 4d ec 75 db 8b 45 f4 8b 55 f8 e8}  //weight: 2, accuracy: High
        $x_1_7 = {53 79 73 74 65 6d 33 32 5c 76 73 73 61 64 6d 69 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 51 75 69 65 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {4d 58 53 31 00}  //weight: 1, accuracy: High
        $x_1_10 = {58 58 53 30 53 00}  //weight: 1, accuracy: High
        $x_2_11 = {8b 55 fc 0f ?? ?? ?? ?? 33 d7 ?? 43 4e 75 ?? 8b 45 f8 8b 55 fc e8 ?? ?? ?? ff}  //weight: 2, accuracy: Low
        $x_1_12 = "easy way If You have really valuable data,you better not waste your time,because there is no other" wide //weight: 1
        $x_1_13 = "<h2>For more specific instructions,please visit your personal home page, there are a few different addresses pointing to" wide //weight: 1
        $x_1_14 = "S#$#pec#$#ia#$#lly f#$#or yo#$#ur P#$#C w#$#as g#$#en#$#era#$#te#$#d p#$#e#$#rs#$#on#$#a#$#l" wide //weight: 1
        $x_1_15 = "\">YOUR PERSONAL ID</i>" wide //weight: 1
        $x_1_16 = "in#$#f#$#or#$#m#$#at#$#ion t#$#o n#$#ot#$#eb#$#oo#$#k (#$#ex#$#e#$#rc#$#i#$#se bo#$#ok !#$#!!)" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Exxroute_C_2147712383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Exxroute.C"
        threat_id = "2147712383"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Exxroute"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "If exist \"%s\" Goto " ascii //weight: 1
        $x_1_2 = {42 65 20 73 75 72 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {23 44 4f 4d 41 49 4e 23 00}  //weight: 1, accuracy: High
        $x_1_4 = {23 49 44 23 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 79 73 74 65 6d 33 32 5c 76 73 73 61 64 6d 69 6e 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 51 75 69 65 74 00}  //weight: 1, accuracy: High
        $x_2_7 = {8b 55 fc 0f b6 54 1a ff 33 d7 88 54 18 ff 43 4e 75 e6 8b 45 f8 8b 55 fc e8 05 05 fe ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Exxroute_D_2147712918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Exxroute.D"
        threat_id = "2147712918"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Exxroute"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "easy way If You have really valuable data,you better not waste your time,because there is no other" wide //weight: 1
        $x_1_2 = "<h2>For more specific instructions,please visit your personal home page, there are a few different addresses pointing to" wide //weight: 1
        $x_1_3 = "S#$#pec#$#ia#$#lly f#$#or yo#$#ur P#$#C w#$#as g#$#en#$#era#$#te#$#d p#$#e#$#rs#$#on#$#a#$#l" wide //weight: 1
        $x_1_4 = "\">YOUR PERSONAL ID</i>" wide //weight: 1
        $x_1_5 = "in#$#f#$#or#$#m#$#at#$#ion t#$#o n#$#ot#$#eb#$#oo#$#k (#$#ex#$#e#$#rc#$#i#$#se bo#$#ok !#$#!!)" wide //weight: 1
        $x_1_6 = "|ki}x|=< kvk" wide //weight: 1
        $x_1_7 = {4d 00 53 00 31 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {46 00 58 00 31 00 31 00 31 00 32 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {83 e8 04 8b 00 8b f0 8b c7 8b d6 e8 17 2c ff ff 85 f6 7e 29 8b 0f 8b d6 83 fa 01 7c 20 0f b7 03 8b f0 83 c6 9f 66 83 ee 1a 73 04 66 83 f0 20 66 89 01 83 c1 02 83 c3 02 4a 85 d2 75 e0}  //weight: 1, accuracy: High
        $x_1_10 = {8b 55 fc 0f b7 54 5a fe 33 d7 66 89 54 58 fe 43 4e 75 e5 8b 45 f8 8b 55 fc e8 00 44 fd ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Exxroute_E_2147716179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Exxroute.E"
        threat_id = "2147716179"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Exxroute"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MemStream" ascii //weight: 1
        $x_1_2 = "wcrypt2" ascii //weight: 1
        $x_1_3 = {68 04 80 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 01 68 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {8b 4c 24 08 8b 44 24 04 83 c1 05 64 89 02 ff d1 c2 0c 00}  //weight: 1, accuracy: High
        $x_1_6 = {ff ff 42 4d 8b 85 ?? ff ff ff 83 c0 36 89 85 ?? ff ff ff c7 85 ?? ff ff ff 36 00 00 00}  //weight: 1, accuracy: Low
        $x_2_7 = {6a 20 53 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 68 00 00 00 c0 53 e8}  //weight: 2, accuracy: Low
        $x_2_8 = {10 08 00 00 76 ?? eb 02 7e ?? 6a 00 6a 00 8b 45 ?? 8b 55 ?? 2d 10 08 00 00 83 da 00}  //weight: 2, accuracy: Low
        $x_2_9 = {ff e8 03 00 00 75 0d 81 7d ?? e8 03 00 00 0f 84}  //weight: 2, accuracy: Low
        $x_2_10 = {75 0b 81 7d ?? 00 00 01 00 76 ?? eb 02 7e ?? 6a 00 8d 45 ?? 50 68 00 00 01 00 8d 85 ?? ?? fe ff 50 53 e8}  //weight: 2, accuracy: Low
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

rule Ransom_Win32_Exxroute_E_2147716180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Exxroute.E!!Exxroute.gen!B"
        threat_id = "2147716180"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Exxroute"
        severity = "Critical"
        info = "Exxroute: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "B: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MemStream" ascii //weight: 1
        $x_1_2 = "wcrypt2" ascii //weight: 1
        $x_1_3 = {68 04 80 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {68 01 68 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {8b 4c 24 08 8b 44 24 04 83 c1 05 64 89 02 ff d1 c2 0c 00}  //weight: 1, accuracy: High
        $x_1_6 = {ff ff 42 4d 8b 85 ?? ff ff ff 83 c0 36 89 85 ?? ff ff ff c7 85 ?? ff ff ff 36 00 00 00}  //weight: 1, accuracy: Low
        $x_2_7 = {6a 20 53 e8 ?? ?? ?? ?? 85 c0 0f 84 ?? ?? ?? ?? 6a 00 68 80 00 00 00 6a 03 6a 00 6a 03 68 00 00 00 c0 53 e8}  //weight: 2, accuracy: Low
        $x_2_8 = {10 08 00 00 76 ?? eb 02 7e ?? 6a 00 6a 00 8b 45 ?? 8b 55 ?? 2d 10 08 00 00 83 da 00}  //weight: 2, accuracy: Low
        $x_2_9 = {ff e8 03 00 00 75 0d 81 7d ?? e8 03 00 00 0f 84}  //weight: 2, accuracy: Low
        $x_2_10 = {75 0b 81 7d ?? 00 00 01 00 76 ?? eb 02 7e ?? 6a 00 8d 45 ?? 50 68 00 00 01 00 8d 85 ?? ?? fe ff 50 53 e8}  //weight: 2, accuracy: Low
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

