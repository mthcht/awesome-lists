rule TrojanSpy_Win32_BrobanNet_A_2147706674_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BrobanNet.A"
        threat_id = "2147706674"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanNet"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QrBoletoAlteracao" ascii //weight: 1
        $x_1_2 = "atualizaGrupoProduto#" ascii //weight: 1
        $x_1_3 = "c:\\progsigem\\" ascii //weight: 1
        $x_1_4 = "boletoretornobanco" ascii //weight: 1
        $x_1_5 = "baixaboleto.VENCIMENTO" ascii //weight: 1
        $x_1_6 = "c:\\banco.txt" ascii //weight: 1
        $x_1_7 = "Atualizando banco. Aguarde . . ." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

