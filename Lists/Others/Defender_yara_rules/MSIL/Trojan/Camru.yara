rule Trojan_MSIL_Camru_A_2147685372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Camru.A"
        threat_id = "2147685372"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Camru"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\mac\\mac\\" ascii //weight: 1
        $x_1_2 = {43 6c 6f 73 65 41 6c 6c 43 68 72 6f 6d 65 42 72 6f 77 73 65 72 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {41 00 6c 00 6c 00 55 00 73 00 65 00 72 00 73 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 ?? ?? 5c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 6c 00 6e 00 6b 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 59 00 61 00 6e 00 64 00 65 00 78 00 2e 00 6c 00 6e 00 6b 00 ?? ?? 59 00 61 00 6e 00 64 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_5 = {5c 00 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00 2e 00 6c 00 6e 00 6b 00 ?? ?? 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 20 00 46 00 69 00 72 00 65 00 66 00 6f 00 78 00}  //weight: 1, accuracy: Low
        $x_1_6 = "\\Opera\\launcher.exe\"" wide //weight: 1
        $x_1_7 = "odnoklassniki.ru/\", \"http" wide //weight: 1
        $x_1_8 = "/search.php?search={searchTerms}\",\"suggest_url\":" wide //weight: 1
        $x_1_9 = "urls_to_restore_on_startup\": [ \"http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

