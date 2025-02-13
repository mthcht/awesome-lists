rule TrojanSpy_Win32_Bancrat_A_2147692931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bancrat.A"
        threat_id = "2147692931"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bancrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CLIENTE REMOTE X LETO" ascii //weight: 1
        $x_1_2 = "MOD_GETSCREEN" ascii //weight: 1
        $x_1_3 = "MOD_COMPACTA_IMG" ascii //weight: 1
        $x_1_4 = "MOD_mOtherBrowser" ascii //weight: 1
        $x_1_5 = "ImgBBAguard" ascii //weight: 1
        $x_1_6 = "ImgBrAviso" ascii //weight: 1
        $x_1_7 = "ImgHsVoltar" ascii //weight: 1
        $x_1_8 = "ImgStContato" ascii //weight: 1
        $x_1_9 = "ImgSicraCodigo" ascii //weight: 1
        $x_1_10 = "ImgCEFIdentificaUser" ascii //weight: 1
        $x_1_11 = "ImgITGetDns" ascii //weight: 1
        $x_1_12 = "SolicitSenha" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

