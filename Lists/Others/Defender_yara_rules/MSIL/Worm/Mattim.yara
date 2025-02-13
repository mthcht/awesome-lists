rule Worm_MSIL_Mattim_A_2147695526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Mattim.A"
        threat_id = "2147695526"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mattim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyloggerRemotoVittima:" wide //weight: 1
        $x_1_2 = "Email N:" wide //weight: 1
        $x_1_3 = "=UpdateAdobe.EXE" wide //weight: 1
        $x_1_4 = "/Config.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

