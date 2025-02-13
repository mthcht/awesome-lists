rule TrojanSpy_Win32_BrobanLaw_A_2147692521_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BrobanLaw.A"
        threat_id = "2147692521"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanLaw"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bola 1 =" wide //weight: 1
        $x_1_2 = "bola 2 =" wide //weight: 1
        $x_1_3 = "ok bolas" wide //weight: 1
        $x_1_4 = "ok entrou no evento" wide //weight: 1
        $x_1_5 = "BolaNosso" ascii //weight: 1
        $x_1_6 = "BolaDele" ascii //weight: 1
        $x_1_7 = "Int_FatorVencimento" ascii //weight: 1
        $x_1_8 = "Linha_Digitavel_Formatada" ascii //weight: 1
        $x_1_9 = "Recebi_Codigo_de_Barras" ascii //weight: 1
        $x_1_10 = "DV_Campo" ascii //weight: 1
        $x_1_11 = "CampoLivre" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

