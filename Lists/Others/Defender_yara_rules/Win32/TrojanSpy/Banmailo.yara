rule TrojanSpy_Win32_Banmailo_A_2147650268_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banmailo.A"
        threat_id = "2147650268"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banmailo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "28435F414219245B27595D1E205E5D" wide //weight: 4
        $x_4_2 = "62585F545E474311785A465641585045117549405C5E43514019" wide //weight: 4
        $x_4_3 = "C785852425E435F5745147B5D4753475F5444" wide //weight: 4
        $x_4_4 = "90637D7366600264036C7C5920435F435656" wide //weight: 4
        $x_2_5 = "79575D50585C1C555C5A" wide //weight: 2
        $x_2_6 = "244257545E0673047603010473" wide //weight: 2
        $x_2_7 = "725443555F535950555B4013575315455042545651421B" wide //weight: 2
        $x_2_8 = "F594550411C505C5B1B5343" wide //weight: 2
        $x_2_9 = "F4746461A5B4752431B525E5D1F5242" wide //weight: 2
        $x_2_10 = "4026543570565D22585C1E5A5F5D" wide //weight: 2
        $x_2_11 = "B0442F5F11552E11715E5C485F" wide //weight: 2
        $x_2_12 = "BLINDADO\\PegaInfoPRINCIPAL" wide //weight: 2
        $x_2_13 = "piramide02@gmail.com" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_2_*))) or
            ((2 of ($x_4_*) and 2 of ($x_2_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

