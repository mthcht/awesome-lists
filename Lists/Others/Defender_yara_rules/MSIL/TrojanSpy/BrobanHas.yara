rule TrojanSpy_MSIL_BrobanHas_A_2147690458_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/BrobanHas.A"
        threat_id = "2147690458"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "BrobanHas"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "B1R2A3D4E5S6C7O8" ascii //weight: 1
        $x_1_2 = "B1R2A3S4I5L6" ascii //weight: 1
        $x_1_3 = "B1R2A3S4I5L6P7J8" ascii //weight: 1
        $x_1_4 = "C1A2I3X4A5" ascii //weight: 1
        $x_1_5 = "L1O2G3_S1E2N3D4" ascii //weight: 1
        $x_1_6 = "L1O2G3G4E5R6" ascii //weight: 1
        $x_1_7 = "EnviaLogs_DoTheMagic" ascii //weight: 1
        $x_1_8 = "FiddleBeforeRequestHandler" ascii //weight: 1
        $x_1_9 = "_w=sendReceipt" wide //weight: 1
        $x_1_10 = "_w=cadastraOnline" wide //weight: 1
        $x_1_11 = ".php?_w=novo" wide //weight: 1
        $x_1_12 = "=boletoForm%" wide //weight: 1
        $x_1_13 = "codigoBarraCobranca=" wide //weight: 1
        $x_1_14 = "txtLeitorOptico=" wide //weight: 1
        $x_1_15 = "Nome do banco:" wide //weight: 1
        $x_1_16 = "gravaPagamento" wide //weight: 1
        $x_1_17 = "txtCodigoBarra" wide //weight: 1
        $x_1_18 = "funcaoFatorVencimento" wide //weight: 1
        $x_1_19 = "HtmlOutputTextBradesco" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

