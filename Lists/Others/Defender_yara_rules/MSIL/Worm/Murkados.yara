rule Worm_MSIL_Murkados_A_2147680363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Murkados.A"
        threat_id = "2147680363"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Murkados"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\ProgramData\\FlashPlayer" wide //weight: 1
        $x_1_2 = "C:\\ProgramData\\ChromeUpdate" wide //weight: 1
        $x_1_3 = "C:\\ProgramData\\start.exe" wide //weight: 1
        $x_1_4 = {42 65 6c 6c 65 67 65 41 74 00 62 65 6c 6c 65 6b 00 44 6f 73 79 61 4f 6c 75 73 74 75 72 00 44 6f 73 79 61 49 6e 64 69 72}  //weight: 1, accuracy: High
        $x_1_5 = {42 65 6c 6c 65 67 65 41 74 00 62 65 6c 6c 65 6b 00 46 6c 61 73 68 56 69 72 75 73 75 00 43 68 72 6f 6d 65 41 63}  //weight: 1, accuracy: High
        $x_1_6 = "taskkill /f /im chrome.exe" wide //weight: 1
        $x_1_7 = "socialmedya.net/php/config.php?type=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

