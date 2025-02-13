rule TrojanSpy_Win32_Banpaes_A_2147596606_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banpaes.gen!A"
        threat_id = "2147596606"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banpaes"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff ff ff ff 11 00 00 00 73 6d 74 70 2e 74 65 72 72 61 2e 63 6f 6d 2e 62 72 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {ff ff ff ff 19 00 00 00 73 6d 74 70 2e 73 65 67 6d 65 6e 74 61 63 61 6f 6c 69 6e 75 78 2e 6e 65 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "certificado digital." ascii //weight: 1
        $x_1_4 = "deve manter esse arquivo em m" ascii //weight: 1
        $x_1_5 = "Informamos que para realizar a atualiza" ascii //weight: 1
        $x_1_6 = "conectado a internet." ascii //weight: 1
        $x_1_7 = "Atualizando...Aguarde..." ascii //weight: 1
        $x_1_8 = "Runtime error     at 00000000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

