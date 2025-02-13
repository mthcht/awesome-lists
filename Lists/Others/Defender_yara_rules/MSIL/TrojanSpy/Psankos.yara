rule TrojanSpy_MSIL_Psankos_A_2147686116_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Psankos.A"
        threat_id = "2147686116"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Psankos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "308"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Z2V0Q2hyb21l" wide //weight: 1
        $x_1_2 = "Z2V0RmlyZWZveA==" wide //weight: 1
        $x_1_3 = "Z2V0U2FmYXJp" wide //weight: 1
        $x_1_4 = "Z2V0TVNO" wide //weight: 1
        $x_1_5 = "Z2V0VHJpbGxpYW4=" wide //weight: 1
        $x_1_6 = "Z2V0SUNR" wide //weight: 1
        $x_1_7 = "Z2V0RGlnc2J5" wide //weight: 1
        $x_1_8 = "Z2V0TmltYnV6eg==" wide //weight: 1
        $x_1_9 = "Z2V0UGlkZ2lu" wide //weight: 1
        $x_1_10 = "Z2V0Rlo=" wide //weight: 1
        $x_1_11 = "Z2V0Q29yZUZUUA==" wide //weight: 1
        $x_1_12 = "Z2V0TGFzdFBhc3M=" wide //weight: 1
        $x_1_13 = "Z2V0V2luZG93c0tleQ==" wide //weight: 1
        $x_1_14 = "Z2V0Qml0Y29pbg==" wide //weight: 1
        $x_100_15 = "<br/><br/>[----- {0} ( {1} ) -----]<br/>" wide //weight: 100
        $x_100_16 = "U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cUnVu" wide //weight: 100
        $x_100_17 = "{0} - Keystrokes" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

