rule Ransom_Win32_Betisrypt_A_2147720933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Betisrypt.A"
        threat_id = "2147720933"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Betisrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\BTCWare\\btcw\\" ascii //weight: 2
        $x_2_2 = "DsrIWhQ4PmbYbkxqL1f4Kdi/SXSZplZ+ZJ0JzRAW/0PPe+i+obKQjPr25iTqQDfP7" ascii //weight: 2
        $x_1_3 = "decrypt your need buy the BTCW-Decrypter" ascii //weight: 1
        $x_1_4 = "no.btcw@protonmail.ch" ascii //weight: 1
        $x_1_5 = "LETTER ATTACH YOUR FILE key.dat!" ascii //weight: 1
        $x_1_6 = "BTCWare-locker." ascii //weight: 1
        $x_1_7 = {00 2e 64 62 5f 6a 6f 75 72 6e 61 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 2e 70 6c 75 73 5f 6d 75 68 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 69 6e 73 62 74 71 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 42 54 43 57 58 58 58 00}  //weight: 1, accuracy: High
        $x_1_11 = "%s-%s-%d-%02d-%02d" ascii //weight: 1
        $x_1_12 = "%s\\key.dat" ascii //weight: 1
        $x_1_13 = "%s\\mfskSkfkls.exe" ascii //weight: 1
        $x_1_14 = "%s\\#_HOW_TO_FIX.inf" ascii //weight: 1
        $x_1_15 = "%s.[%s].btcware" ascii //weight: 1
        $x_1_16 = "/c vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_17 = "/c bcdedit.exe /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_18 = "/c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_2_19 = {74 4e 81 7d f0 e8 03 00 00 b8 01 00 00 00 68 f0 03 00 00}  //weight: 2, accuracy: High
        $x_2_20 = {83 fe 02 7d 05 83 f8 02 74 17 83 f8 03 74 0a 83 f8 02 74 05 83 f8 04 75 08 8d 46 41}  //weight: 2, accuracy: High
        $x_2_21 = {b8 42 4d 00 00 66 89 45 dc 0f 11 45 c8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((5 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Betisrypt_B_2147721637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Betisrypt.B"
        threat_id = "2147721637"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Betisrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\HELP.hta" wide //weight: 10
        $x_10_2 = "DECRYPTINFO" wide //weight: 10
        $x_10_3 = "NUCLEAR" wide //weight: 10
        $x_10_4 = "/c vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 10
        $x_10_5 = "/c bcdedit.exe /set {default} recoveryenabled No" wide //weight: 10
        $x_10_6 = "/c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" wide //weight: 10
        $x_10_7 = "nocturnalnocturnalnocturnalnocturnal" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Betisrypt_B_2147721637_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Betisrypt.B"
        threat_id = "2147721637"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Betisrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!#_DECRYPT_#!.inf" ascii //weight: 1
        $x_1_2 = "!#_READ_ME_#!.hta" ascii //weight: 1
        $x_1_3 = ".onyon" ascii //weight: 1
        $x_1_4 = "nintendonx@qq.com" ascii //weight: 1
        $x_1_5 = "%s-%s-%d-%02d-%02d" ascii //weight: 1
        $x_1_6 = "/c vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_7 = "/c bcdedit.exe /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_8 = "/c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_9 = {00 2e 64 62 5f 6a 6f 75 72 6e 61 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 2e 70 6c 75 73 5f 6d 75 68 64 00}  //weight: 1, accuracy: High
        $x_2_11 = {83 fe 02 7d 05 83 f8 02 74 17 83 f8 03 74 0a 83 f8 02 74 05 83 f8 04 75 08 8d 46 41}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Betisrypt_A_2147722703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Betisrypt.A!!Betisrypt.gen!A"
        threat_id = "2147722703"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Betisrypt"
        severity = "Critical"
        info = "Betisrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!#_DECRYPT_#!.inf" ascii //weight: 1
        $x_1_2 = "!#_READ_ME_#!.hta" ascii //weight: 1
        $x_1_3 = ".onyon" ascii //weight: 1
        $x_1_4 = "nintendonx@qq.com" ascii //weight: 1
        $x_1_5 = "%s-%s-%d-%02d-%02d" ascii //weight: 1
        $x_1_6 = "/c vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_7 = "/c bcdedit.exe /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_8 = "/c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_9 = {00 2e 64 62 5f 6a 6f 75 72 6e 61 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 2e 70 6c 75 73 5f 6d 75 68 64 00}  //weight: 1, accuracy: High
        $x_2_11 = {83 fe 02 7d 05 83 f8 02 74 17 83 f8 03 74 0a 83 f8 02 74 05 83 f8 04 75 08 8d 46 41}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Betisrypt_A_2147722703_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Betisrypt.A!!Betisrypt.gen!A"
        threat_id = "2147722703"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Betisrypt"
        severity = "Critical"
        info = "Betisrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "70"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\HELP.hta" wide //weight: 10
        $x_10_2 = "DECRYPTINFO" wide //weight: 10
        $x_10_3 = "NUCLEAR" wide //weight: 10
        $x_10_4 = "/c vssadmin.exe Delete Shadows /All /Quiet" wide //weight: 10
        $x_10_5 = "/c bcdedit.exe /set {default} recoveryenabled No" wide //weight: 10
        $x_10_6 = "/c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" wide //weight: 10
        $x_10_7 = "nocturnalnocturnalnocturnalnocturnal" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Betisrypt_D_2147723553_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Betisrypt.D"
        threat_id = "2147723553"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Betisrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_2 = "/c bcdedit.exe /set {default} recoveryenabled No" ascii //weight: 1
        $x_1_3 = "/c bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_4 = "nocturnalnocturnalnocturnalnocturnal" ascii //weight: 1
        $x_1_5 = {00 25 73 2e 5b 25 73 5d 2d 69 64 2d 25 58 2e}  //weight: 1, accuracy: High
        $x_1_6 = "PGltZyBzcmM9J2RhdGE6aW1hZ2UvcG5nO2Jhc2U2NCxpVkJPUg0K" ascii //weight: 1
        $x_2_7 = {83 fe 02 7d 05 83 f8 02 74 17 83 f8 03 74 0a 83 f8 02 74 05 83 f8 04 75 08 8d 46 41}  //weight: 2, accuracy: High
        $x_1_8 = {68 10 66 00 00 ff 75 ?? ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8d 45 ?? 6a 00 50 6a 04 ff 75 ?? ff d6}  //weight: 1, accuracy: Low
        $x_2_9 = {68 00 00 a0 00 68 ?? ?? ?? ?? 53 ff 15 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 8d 45 ?? 68 00 00 a0 00 50 6a 00 6a 00 6a 01 6a 00 ff 75 ?? ff d6}  //weight: 2, accuracy: Low
        $x_1_10 = {ff d7 56 ff d3 6a 00 6a 00 6a 03 6a 00 6a 01 68 00 01 00 40 ff 75 ?? ff 15}  //weight: 1, accuracy: Low
        $x_1_11 = {ff 75 20 8d 4d 10 0f 43 4d 10 51 56 ff d7 56 ff d3 8b 45 ?? 85 c0 74 0e}  //weight: 1, accuracy: Low
        $x_1_12 = {6a 01 56 53 ff 15 ?? ?? ?? ?? 8b 45 24 83 f8 10 72 42 8b 4d 10 40 3d 00 10 00 00 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

