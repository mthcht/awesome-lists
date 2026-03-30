rule Trojan_MSIL_ConvertRat_AMTB_2147965894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ConvertRat!AMTB"
        threat_id = "2147965894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ConvertRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "--hide-crash-restore-bubble --restore-last-session" ascii //weight: 2
        $x_2_2 = "Exception while creating shortcut.   U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cVW5pbnN0YWxsXA==" ascii //weight: 2
        $x_1_3 = "pages/confirmpage.xaml" ascii //weight: 1
        $x_1_4 = "pages/firstpage.xaml" ascii //weight: 1
        $x_1_5 = "pages/mainwindow.xaml" ascii //weight: 1
        $x_4_6 = "https://psotimim.com/new" ascii //weight: 4
        $x_1_7 = "EncodeJson" ascii //weight: 1
        $x_1_8 = "get_UserName" ascii //weight: 1
        $x_1_9 = "RelaunchChrome" ascii //weight: 1
        $x_1_10 = "ShutdownChrome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 6 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

