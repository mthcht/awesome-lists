rule Trojan_MSIL_Hiutex_A_2147645009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Hiutex.gen!A"
        threat_id = "2147645009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hiutex"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ValuefakeErrorTitle" wide //weight: 1
        $x_1_2 = "ValuefakeErrorMessage" wide //weight: 1
        $x_1_3 = "BOT BIN" wide //weight: 1
        $x_1_4 = "socks5.php" wide //weight: 1
        $x_1_5 = "&botver=" ascii //weight: 1
        $x_1_6 = "&country=" ascii //weight: 1
        $x_1_7 = "&winver=" ascii //weight: 1
        $x_1_8 = {77 69 6e 33 32 5f 6c 6f 67 69 63 61 6c 64 69 73 6b 2e 64 65 76 69 63 65 69 64 3d 22 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

