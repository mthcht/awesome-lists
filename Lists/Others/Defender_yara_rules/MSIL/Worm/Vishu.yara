rule Worm_MSIL_Vishu_A_2147694584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Vishu.A"
        threat_id = "2147694584"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Vishu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c del /q /s /f \"C:\\Users\\%USERNAME%\\AppData\\Local\\Google\\Chrome\\User Data\"" wide //weight: 1
        $x_1_2 = "\" ( ECHO ) ELSE (taskkill /f /im explorer.exe" wide //weight: 1
        $x_1_3 = "wscript.exe invis.vbs run.bat %*" wide //weight: 1
        $x_1_4 = "micosoft.hotmil.com@gmail.com" wide //weight: 1
        $x_1_5 = {72 75 6e 73 68 75 74 00 72 75 6e 70 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

