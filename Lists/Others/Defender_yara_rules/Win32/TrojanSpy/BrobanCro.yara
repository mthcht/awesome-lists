rule TrojanSpy_Win32_BrobanCro_A_2147690446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/BrobanCro.A"
        threat_id = "2147690446"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "BrobanCro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\elgooG\\tfosorciM\\" ascii //weight: 1
        $x_1_2 = "gnp.noci" ascii //weight: 1
        $x_1_3 = "nosj.tsefinaM" ascii //weight: 1
        $x_1_4 = "\\sovitacilpa ed sodaD\\" ascii //weight: 1
        $x_10_5 = "oDoc.indexOf(\"LOCAL DE PAGAMENTO\")" ascii //weight: 10
        $x_10_6 = "0<=l.indexOf(f(\"YBPNY QR CNTNZRAGB\")" ascii //weight: 10
        $x_10_7 = {2e 73 69 63 6f 6f 62 2e 63 6f 6d 2e 62 72 2f [0-8] 76 61 72 20 75 72 6c 64 61 76 65 7a 54 69 74 75 6c 6f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

