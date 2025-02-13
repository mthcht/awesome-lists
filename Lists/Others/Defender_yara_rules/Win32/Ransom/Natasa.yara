rule Ransom_Win32_Natasa_A_2147714806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Natasa.A"
        threat_id = "2147714806"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Natasa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "satana" ascii //weight: 1
        $x_2_2 = "threadAdminFlood: %s %s %s" ascii //weight: 2
        $x_1_3 = "%s\\VSSADMIN.EXE" ascii //weight: 1
        $x_1_4 = "dwSzBTC" ascii //weight: 1
        $x_1_5 = "dwSzMail" ascii //weight: 1
        $x_1_6 = "dwMailSelector" ascii //weight: 1
        $x_1_7 = "dwBtcSelector" ascii //weight: 1
        $x_1_8 = "ZeroSecNum:%d" ascii //weight: 1
        $x_1_9 = "FirstZero:%d" ascii //weight: 1
        $x_1_10 = "LastZero:%d" ascii //weight: 1
        $x_2_11 = "id=%d&code=%d&sdata=%d.%d.%d" ascii //weight: 2
        $x_2_12 = "%d&name=%s&md5=%s&dlen=%s" ascii //weight: 2
        $x_1_13 = "XOR key=0x%X" ascii //weight: 1
        $x_1_14 = "%s: EXCEPT!!" ascii //weight: 1
        $x_1_15 = "=======EEEEEEEEEEEEEE=========" ascii //weight: 1
        $x_1_16 = "First Phase Done" ascii //weight: 1
        $x_1_17 = "Two Phase Done" ascii //weight: 1
        $x_1_18 = "VOLUME:File: %s" ascii //weight: 1
        $x_1_19 = {32 c2 32 c3 34 ?? 0f b6 d0 88 81 ?? ?? ?? ?? 88 8a ?? ?? ?? ?? 41 81 f9 00 01 00 00 7c}  //weight: 1, accuracy: Low
        $x_1_20 = {c6 04 02 00 c6 00 00 8a 14 06 2a d1 fe ca 88 14 07 41 40 3b 4d f8 76 e5}  //weight: 1, accuracy: High
        $x_2_21 = {58 83 e8 09 89 45 fc 8b 45 fc 83 e8 ?? 89 45 fc 68 ?? ?? 00 00 8b 4d fc 8b 51 04 ff d2}  //weight: 2, accuracy: Low
        $x_1_22 = {c6 44 03 fd 01 8b 4d ec c6 44 0b fe 55 8b 55 ec c6 44 13 ff aa}  //weight: 1, accuracy: High
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

rule Ransom_Win32_Natasa_A_2147714807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Natasa.A!!Natasa.gen!A"
        threat_id = "2147714807"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Natasa"
        severity = "Critical"
        info = "Natasa: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "satana" ascii //weight: 1
        $x_2_2 = "threadAdminFlood: %s %s %s" ascii //weight: 2
        $x_1_3 = "%s\\VSSADMIN.EXE" ascii //weight: 1
        $x_1_4 = "dwSzBTC" ascii //weight: 1
        $x_1_5 = "dwSzMail" ascii //weight: 1
        $x_1_6 = "dwMailSelector" ascii //weight: 1
        $x_1_7 = "dwBtcSelector" ascii //weight: 1
        $x_1_8 = "ZeroSecNum:%d" ascii //weight: 1
        $x_1_9 = "FirstZero:%d" ascii //weight: 1
        $x_1_10 = "LastZero:%d" ascii //weight: 1
        $x_2_11 = "id=%d&code=%d&sdata=%d.%d.%d" ascii //weight: 2
        $x_2_12 = "%d&name=%s&md5=%s&dlen=%s" ascii //weight: 2
        $x_1_13 = "XOR key=0x%X" ascii //weight: 1
        $x_1_14 = "%s: EXCEPT!!" ascii //weight: 1
        $x_1_15 = "=======EEEEEEEEEEEEEE=========" ascii //weight: 1
        $x_1_16 = "First Phase Done" ascii //weight: 1
        $x_1_17 = "Two Phase Done" ascii //weight: 1
        $x_1_18 = "VOLUME:File: %s" ascii //weight: 1
        $x_1_19 = {32 c2 32 c3 34 ?? 0f b6 d0 88 81 ?? ?? ?? ?? 88 8a ?? ?? ?? ?? 41 81 f9 00 01 00 00 7c}  //weight: 1, accuracy: Low
        $x_1_20 = {c6 04 02 00 c6 00 00 8a 14 06 2a d1 fe ca 88 14 07 41 40 3b 4d f8 76 e5}  //weight: 1, accuracy: High
        $x_2_21 = {58 83 e8 09 89 45 fc 8b 45 fc 83 e8 ?? 89 45 fc 68 ?? ?? 00 00 8b 4d fc 8b 51 04 ff d2}  //weight: 2, accuracy: Low
        $x_1_22 = {c6 44 03 fd 01 8b 4d ec c6 44 0b fe 55 8b 55 ec c6 44 13 ff aa}  //weight: 1, accuracy: High
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

