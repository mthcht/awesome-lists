rule TrojanSpy_Win32_Fobansug_A_2147706845_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fobansug.A"
        threat_id = "2147706845"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fobansug"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "E51823D379A34EF83FEF7993B45790528AB141ED1A22D572E70B32D81D6CF25DFD39F85B87BE58FD073CF3" ascii //weight: 2
        $x_2_2 = "202631E10B31FD082ED80018C9628DAE6D94A340CC658BC116D40735C1548ACA0D21DF64FD24D51122DD152B38F121C3668FA058819745F63FD00F34FD32C77DA7" ascii //weight: 2
        $x_1_3 = "A7A652F654D411D41622A25F8EBC698F" ascii //weight: 1
        $x_1_4 = "9985BC6E98A54EE21EC80928001FD91FDD1DD51024D6" ascii //weight: 1
        $x_1_5 = "A0BC649746D71828DB0A48E942DD6CDE6FAA4F" ascii //weight: 1
        $x_1_6 = "43DE1CD1021BC57AB550F63E" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

