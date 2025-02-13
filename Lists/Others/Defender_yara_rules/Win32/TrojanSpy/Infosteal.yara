rule TrojanSpy_Win32_Infosteal_2147630371_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Infosteal"
        threat_id = "2147630371"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Infosteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Arquivos de programas\\ws2_32.exe" ascii //weight: 1
        $x_1_2 = "c:\\bk.dt" ascii //weight: 1
        $x_1_3 = "http://www.ssl000.com.br/www/inf.php" ascii //weight: 1
        $x_1_4 = "http://ssl000.com.br/dll/" ascii //weight: 1
        $x_1_5 = "checkip.dyndns.org" ascii //weight: 1
        $x_1_6 = "UuidCreateSequential" ascii //weight: 1
        $x_1_7 = "SHD Firmware:" ascii //weight: 1
        $x_1_8 = "Win Diretorico:" ascii //weight: 1
        $x_1_9 = "@gmail" ascii //weight: 1
        $x_1_10 = "PC Mac:" ascii //weight: 1
        $x_1_11 = "IP Privado:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule TrojanSpy_Win32_Infosteal_A_2147733305_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Infosteal.A"
        threat_id = "2147733305"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Infosteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Tetris.bmp" wide //weight: 1
        $x_1_2 = "\\Scores.dat" wide //weight: 1
        $x_1_3 = "lblNewGaDFGDFGDFGDFG" wide //weight: 1
        $x_1_4 = "txtEnterNaDFGDFGDFGDFG" wide //weight: 1
        $x_1_5 = ".0/010201101/0.0/1011020/10110111101/0/101//0/1//00/1020.0/00/10///010201/10/0.00//01//1/1/00/1//01/10011001/0//0.0/1020" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

