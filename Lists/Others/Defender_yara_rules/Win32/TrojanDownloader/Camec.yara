rule TrojanDownloader_Win32_Camec_A_2147637845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Camec.A"
        threat_id = "2147637845"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4246575143" wide //weight: 1
        $x_1_2 = "63564B59515C1078740A10" wide //weight: 1
        $x_1_3 = "675A5703026F7F4055425144595E5763494344555D" wide //weight: 1
        $x_1_4 = "1E564155" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Camec_G_2147650648_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Camec.G"
        threat_id = "2147650648"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Desabilita_UAC" ascii //weight: 5
        $x_5_2 = ";Password=" wide //weight: 5
        $x_2_3 = "jflash.dll" wide //weight: 2
        $x_2_4 = "_Crypt_Senha1" ascii //weight: 2
        $x_1_5 = "Grava_Registro" ascii //weight: 1
        $x_1_6 = "Ler_Registro" ascii //weight: 1
        $x_1_7 = "Registra_BHO" ascii //weight: 1
        $x_1_8 = "Envia_Aviso" ascii //weight: 1
        $x_1_9 = "Carrega_Dic" ascii //weight: 1
        $x_1_10 = "Carrega_Dados" ascii //weight: 1
        $x_1_11 = "CurrentVersion\\Explorer\\Browser Helper Objects" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 7 of ($x_1_*))) or
            ((1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Camec_E_2147652417_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Camec.E"
        threat_id = "2147652417"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 5d 0c 89 5d 88 b8 03 40 00 00 89 45 80 8b 4d 10 89 8d 78 ff ff ff ba 08 40 00 00 89 95 70 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {8b 8d 1c ff ff ff 51 8b 55 08 8b 42 6c 8b 48 04 51 8b 35}  //weight: 1, accuracy: High
        $x_1_3 = {c7 45 c4 02 00 00 80 8b 46 6c 8b 0e 8d 55 c8 52 8d 50 04 52 8d 55 dc 52 8d 50 10 52 83 c0 0c 50}  //weight: 1, accuracy: High
        $x_1_4 = {8b 55 28 8b 02 89 85 e0 fe ff ff 89 b5 d8 fe ff ff 8b 47 6c 8b 48 34 89 8d d0 fe ff ff 89 b5 c8 fe ff ff 8b 50 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Camec_I_2147652487_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Camec.I"
        threat_id = "2147652487"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "47535246434606041B504B5D11194B18" wide //weight: 1
        $x_1_2 = "697559465C50" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Camec_K_2147653903_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Camec.K"
        threat_id = "2147653903"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Camec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 3b f3 0f 8c ?? 00 00 00 66 6b ff 40 66 8b 45 dc 0f 80 ?? 01 00 00 66 03 fe 0f 80 ?? 01 00 00 66 05 06 00 0f 80 ?? 01 00 00 66 3d 08 00}  //weight: 1, accuracy: Low
        $x_1_2 = {40 00 6a 70 8d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ff ?? 6a 65 8d ?? ?? ?? ?? ?? ?? ?? ?? 6a 66}  //weight: 1, accuracy: Low
        $x_1_3 = "wCBGbaRKwZ0GwCRswC0mJCwVwgcGbaRswCDGwaBQwCJGpSRKwSsmwkj4wZjGpapkwSTmwSjuwZJCpkj4wZ0mJkjuwCcmJCRnwZTGJaBgwSTmpD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

