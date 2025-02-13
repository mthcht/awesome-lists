rule TrojanSpy_Win32_BrobanFep_A_2147690455_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BrobanFep.A"
        threat_id = "2147690455"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanFep"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\d{6} +\\\\d +\\\\d{14}/g" ascii //weight: 1
        $x_1_2 = "|boleto|" ascii //weight: 1
        $x_1_3 = "|ITAU|" ascii //weight: 1
        $x_1_4 = "|BRADESCO|" ascii //weight: 1
        $x_1_5 = "|SANTANDER|" ascii //weight: 1
        $x_1_6 = "|CAIXA|" ascii //weight: 1
        $x_1_7 = "|getBilletNumber|" ascii //weight: 1
        $x_1_8 = "|Campocodigobarra|" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

