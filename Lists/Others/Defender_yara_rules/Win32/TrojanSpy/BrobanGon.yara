rule TrojanSpy_Win32_BrobanGon_A_2147690448_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BrobanGon.A"
        threat_id = "2147690448"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanGon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tTituloBradesco" ascii //weight: 1
        $x_1_2 = "tSantander" ascii //weight: 1
        $x_1_3 = "tTituloHsbcJuridico" ascii //weight: 1
        $x_1_4 = "tTituloSicoob" ascii //weight: 1
        $x_1_5 = "tVencimento" ascii //weight: 1
        $x_1_6 = "txtNovaLinha" ascii //weight: 1
        $x_1_7 = "DataVencimento" wide //weight: 1
        $x_1_8 = "boletoRegistradoDdaForm" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

