rule Trojan_MSIL_Komarwai_A_2147697170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Komarwai.A"
        threat_id = "2147697170"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Komarwai"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = "komargames.ru/" wide //weight: 4
        $x_4_2 = {73 00 68 00 75 00 74 00 64 00 6f 00 77 00 6e 00 [0-4] 2d 00 73 00 20 00 2d 00 74 00 20 00 30 00 30 00 20 00 2d 00 66 00}  //weight: 4, accuracy: Low
        $x_2_3 = "wiadebug.exe" ascii //weight: 2
        $x_1_4 = "set_mouseHook" ascii //weight: 1
        $x_1_5 = "ScreenshotToClipboard" ascii //weight: 1
        $x_1_6 = "set_GetDrives" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 3 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

