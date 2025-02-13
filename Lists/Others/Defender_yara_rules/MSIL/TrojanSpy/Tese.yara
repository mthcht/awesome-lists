rule TrojanSpy_MSIL_Tese_A_2147696219_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Tese.A"
        threat_id = "2147696219"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Tese"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%APPDATA%\\Microsoft Manager APP\\InjectionSQL\\InjectionSQL.exe" wide //weight: 1
        $x_1_2 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_3 = "%APPDATA%\\GemWare" wide //weight: 1
        $x_1_4 = "CryptoDB\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

