rule TrojanSpy_Win32_Qipi_A_2147636677_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Qipi.A"
        threat_id = "2147636677"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Qipi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "EMAILS EM MASSA DA LISTA DE CONTATOS DO MSN V-5.000" ascii //weight: 3
        $x_3_2 = "programs\\startup\\jmsdbrcfg.exe" ascii //weight: 3
        $x_2_3 = "tmativamsnTimer" ascii //weight: 2
        $x_1_4 = "gsmtp185.google.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

