rule TrojanSpy_Win32_Brajur_A_2147605493_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Brajur.A"
        threat_id = "2147605493"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Brajur"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {a5 a5 a4 5e 46 ff 4d dc 0f 85 ?? ?? ff ff 6a 00 6a 5b 6a 5d 6a 00 8b 4d}  //weight: 10, accuracy: Low
        $x_10_2 = {8b 45 10 81 38 01 01 00 00 75 13 8b 45 10 81 78 04 10 2a 00 00 75 07 33 c0 a3 ?? ?? ?? ?? 8b 45 10 81 38 01 01 00 00 75 13 8b 45 10 81 78 04 11 1d 00 00 75 07}  //weight: 10, accuracy: Low
        $x_1_3 = ".onsubmit = validaManda;" ascii //weight: 1
        $x_1_4 = "[VERSAO]" ascii //weight: 1
        $x_1_5 = "TIdDecoderBinHex4" ascii //weight: 1
        $x_1_6 = "<serialhd>" ascii //weight: 1
        $x_1_7 = "</computername>" ascii //weight: 1
        $x_1_8 = "FrmPrincipal" ascii //weight: 1
        $x_1_9 = "<TEXTOARQUIVO>" ascii //weight: 1
        $x_1_10 = "<NOMEARQUIVO>" ascii //weight: 1
        $x_1_11 = "<MENSAGEM>" ascii //weight: 1
        $x_1_12 = "AVG E-mail Scanner" ascii //weight: 1
        $x_1_13 = "Norton AntiVirus" ascii //weight: 1
        $x_1_14 = "Bradesco Net Empresa" ascii //weight: 1
        $x_1_15 = "Evento:" ascii //weight: 1
        $x_1_16 = "Arquivo Configura" ascii //weight: 1
        $x_1_17 = "del /q /f \"%s" ascii //weight: 1
        $x_1_18 = "links[i].onclick.toString().indexOf(" ascii //weight: 1
        $x_1_19 = "</senha>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

