rule Worm_MSIL_Veraeser_A_2147685559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Veraeser.A"
        threat_id = "2147685559"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Veraeser"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Send2Usb.exe" ascii //weight: 1
        $x_1_2 = "timer_usb_Tick" ascii //weight: 1
        $x_1_3 = "chUsb" ascii //weight: 1
        $x_1_4 = "AddStartUpKey" ascii //weight: 1
        $x_1_5 = "searchUsb" ascii //weight: 1
        $x_1_6 = "[*FileSize*]" wide //weight: 1
        $x_1_7 = ".sendproxy" wide //weight: 1
        $x_1_8 = "//TempInfo.html" wide //weight: 1
        $x_1_9 = "ftp://31.170.167.92//" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

