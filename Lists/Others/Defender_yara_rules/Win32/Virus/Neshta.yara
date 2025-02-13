rule Virus_Win32_Neshta_C_2147603721_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Neshta.C"
        threat_id = "2147603721"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Neshta"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {cf f0 fb e2 69 f2 e0 ed ed e5 20 f3 f1 69 ec 20 7e f6 69 ea e0 e2 fb ec 7e 20 e1 e5 eb e0 f0 f3 f1 5f ea 69 ec 20 e4 e7 ff f3 f7 e0 f2 e0 ec 2e 20 c0 eb ff ea f1 e0 ed e4 f0 20 d0 fb e3 ee f0 e0 e2 69 f7 2c 20 e2 e0 ec 20 f2 e0 ea f1 e0 ec e0 20 3a 29 20 c2 ee f1 e5 ed fc 20 2d 20 ea e5 ef f1 ea e0 ff 20 ef e0 f0 e0 2e 2e 2e 20 c0 eb}  //weight: 10, accuracy: High
        $x_1_2 = "Delphi-the best. Fuck off all the rest. Neshta 1.0 Made in Belarus." ascii //weight: 1
        $x_1_3 = "Best regards 2 Tommy Salo. [Nov-2005] yours [Dziadulja Apanas]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

