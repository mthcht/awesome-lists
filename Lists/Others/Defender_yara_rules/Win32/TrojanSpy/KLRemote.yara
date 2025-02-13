rule TrojanSpy_Win32_KLRemote_2147691052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/KLRemote"
        threat_id = "2147691052"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "KLRemote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Servidor - Operador" ascii //weight: 1
        $x_1_2 = "TimeOut" ascii //weight: 1
        $x_1_3 = "MaxCon." ascii //weight: 1
        $x_1_4 = "Porta" ascii //weight: 1
        $x_1_5 = "Senha" ascii //weight: 1
        $x_1_6 = "Desativar Operador" ascii //weight: 1
        $x_1_7 = "Sistem Operacional" ascii //weight: 1
        $x_1_8 = "Processador" ascii //weight: 1
        $x_1_9 = "Registro de Log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

