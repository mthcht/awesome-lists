rule TrojanSpy_Win32_Broftuk_A_2147687065_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Broftuk.A"
        threat_id = "2147687065"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Broftuk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "DD0739EE1B1079EF2FEF2D1033E81AC065C274B04A" wide //weight: 4
        $x_4_2 = "33DA0DC277F462D64138221B181D0578F861DD43220760905C9E514F86D670" wide //weight: 4
        $x_2_3 = "B4BA6A88B567E74FDC032EDC056882BE8E84A142FD3FF2" wide //weight: 2
        $x_2_4 = "C34AF51439E05D3A37ED0525DDB05B85F56C89AB47E61A" wide //weight: 2
        $x_2_5 = "CA4CF3220BC46891BD64CE7BA68B9F4EE1162ACA6E8CFA70C97C8" wide //weight: 2
        $x_2_6 = "96BF76A95E9488F0689644F053F729D76F8ABDB848" wide //weight: 2
        $x_2_7 = "ADBB69A04EFF2ACC588EB66089BA61F731CE6183AEA447F03DE7" wide //weight: 2
        $x_2_8 = "E3709D5B80A950F672A85D9A4CF72236CF6F81A34FC7629B569E" wide //weight: 2
        $x_2_9 = "879B46E811381E25DC09123FE50627D4A4AB47FF23" wide //weight: 2
        $x_2_10 = "A1B55C82AA52343FE6031831D7709D5D2DD26E80A3" wide //weight: 2
        $x_2_11 = "C46CA25480FF69DF1FDF1D0024DE1DC577B14C29D81DDC" wide //weight: 2
        $x_1_12 = "30DE133DF62E0872" wide //weight: 1
        $x_1_13 = "2428D40A38DC09" wide //weight: 1
        $x_1_14 = "B741F224D5729D4D251B" wide //weight: 1
        $x_1_15 = "94A9638F40F111C4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

