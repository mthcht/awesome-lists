rule TrojanSpy_Win32_Zapemli_A_2147650202_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Zapemli.A"
        threat_id = "2147650202"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Zapemli"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "00147C5B5846524B57" wide //weight: 4
        $x_4_2 = "001857504545411F533A55" wide //weight: 4
        $x_2_3 = "0024435747405E5253311E264E54" wide //weight: 2
        $x_2_4 = "0026475B5B5A5856592C1E264E5416" wide //weight: 2
        $x_2_5 = "0022475B5B5F5958426C553B53" wide //weight: 2
        $x_2_6 = "00506C765A41595D5923542652116644582444205B1477515D5343" wide //weight: 2
        $x_2_7 = "00185C415445441F533A55" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

