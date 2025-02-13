rule Ransom_MSIL_Hayir_SK_2147755811_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Hayir.SK!MTB"
        threat_id = "2147755811"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hayir"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TIMEDELETE" wide //weight: 2
        $x_2_2 = "USBSPREAD" wide //weight: 2
        $x_5_3 = "\\WindowsKeyboardDriver.exe" wide //weight: 5
        $x_5_4 = "\\Microsoft\\Windows\\wallpaper.jpg" wide //weight: 5
        $x_5_5 = "\\Microsoft\\Windows\\backup_wall.jpg" wide //weight: 5
        $x_5_6 = "\\Microsoft\\delete_program.del" wide //weight: 5
        $x_20_7 = "Your Files were deleted!! good bye!" wide //weight: 20
        $x_20_8 = "/C choice /C Y /N /D Y /T 3 & Del" wide //weight: 20
        $x_20_9 = "Your files will delete end of this time" wide //weight: 20
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 1 of ($x_5_*) and 1 of ($x_2_*))) or
            ((1 of ($x_20_*) and 2 of ($x_5_*))) or
            ((2 of ($x_20_*))) or
            (all of ($x*))
        )
}

