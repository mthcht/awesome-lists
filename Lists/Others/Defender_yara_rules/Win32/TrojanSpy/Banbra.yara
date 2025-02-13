rule TrojanSpy_Win32_Banbra_I_2147618805_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banbra.I"
        threat_id = "2147618805"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banbra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 65 6e 68 61 74 78 74 00 00}  //weight: 10, accuracy: High
        $x_10_2 = {53 65 6e 68 61 4a 75 6a 75 00 00}  //weight: 10, accuracy: High
        $x_2_3 = "https://bradesconetempresa.com.br -  Bradesco - Colocando voc" ascii //weight: 2
        $x_2_4 = {57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 00 00 52 00 65 00 67 00 57 00 72 00 69 00 74 00 65 00}  //weight: 2, accuracy: High
        $x_2_5 = "Leitor SmartCard n" wide //weight: 2
        $x_1_6 = " sempre a frente" ascii //weight: 1
        $x_1_7 = "Bradesco Net Empresa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Banbra_M_2147632446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banbra.M"
        threat_id = "2147632446"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banbra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {3e 3e 20 42 61 6e 6b 20 4e 61 6d 65 20 2d 20 00 3e 3e 20 43 6c 69 70 42 6f 61 72 64 20 2d 20 00}  //weight: 2, accuracy: High
        $x_2_2 = {21 4d 63 2e 41 66 65 65 21 00}  //weight: 2, accuracy: High
        $x_1_3 = {26 63 6f 6e 74 65 6e 74 32 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = "key.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banbra_M_2147632446_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banbra.M"
        threat_id = "2147632446"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banbra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 6a 73 6e 00 00 00 00 67 7c 67 78 6c 69 7a 72 39 32 26 6e 6e 66 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 55 fb 8a 14 17 80 e2 0a 32 c2 33 d2 8a d3 8a 14 16 80 e2 f0 80 e2 f0 02 d0 33 c0 8a c3 8b 4d fc 88 14 01 fe 45 fb [0-16] 33 d2 8a 55 fb 3b c2 ?? 04 c6 45 fb 00 43 fe 4d fa 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Banbra_AI_2147661600_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banbra.AI"
        threat_id = "2147661600"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banbra"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "N Mae: " wide //weight: 1
        $x_1_2 = "Dta Nasc: " wide //weight: 1
        $x_1_3 = "SeCard: " wide //weight: 1
        $x_1_4 = "Apelido: " wide //weight: 1
        $x_1_5 = "AsElle: " wide //weight: 1
        $x_1_6 = "prakeim=" wide //weight: 1
        $x_1_7 = {20 00 2d 00 20 00 41 00 7a 00 75 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_8 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6c 00 69 00 76 00 65 00 66 00 72 00 6f 00 6d 00 2e 00 67 00 65 00 2f 00 6d 00 6f 00 64 00 75 00 6c 00 65 00 73 00 2f 00 6d 00 6f 00 64 00 5f 00 73 00 77 00 66 00 6f 00 62 00 6a 00 65 00 63 00 74 00 2f 00 65 00 6e 00 66 00 6f 00 2e 00 70 00 68 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_9 = {6d 00 69 00 63 00 61 00 20 00 46 00 65 00 64 00 65 00 72 00 61 00 6c 00 20 00 2d 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 45 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

