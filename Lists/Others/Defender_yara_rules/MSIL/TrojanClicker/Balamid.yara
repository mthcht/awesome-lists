rule TrojanClicker_MSIL_Balamid_A_2147685071_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Balamid.A"
        threat_id = "2147685071"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\csrss.exe" ascii //weight: 1
        $x_1_2 = "baglanmadi" ascii //weight: 1
        $x_1_3 = "/toy2.txt" ascii //weight: 1
        $x_1_4 = "onmousedown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_MSIL_Balamid_A_2147685071_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Balamid.A"
        threat_id = "2147685071"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/reklam/728x90.html" ascii //weight: 1
        $x_1_2 = "akeegleenaondckknlhflmihfgkpbane" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_MSIL_Balamid_A_2147685071_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Balamid.A"
        threat_id = "2147685071"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\task64.exe" ascii //weight: 1
        $x_1_2 = "\\system.exe" ascii //weight: 1
        $x_1_3 = "wintask32.com" ascii //weight: 1
        $x_1_4 = "/toy2.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_MSIL_Balamid_A_2147685071_3
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Balamid.A"
        threat_id = "2147685071"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 72 65 6b 6c 61 6d 2f [0-12] 78 [0-12] 2e 68 74 6d}  //weight: 1, accuracy: Low
        $x_1_2 = {2f 00 72 00 65 00 6b 00 6c 00 61 00 6d 00 2f [0-32] 00 78 [0-32] 00 2e 00 68 00 74 00 6d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanClicker_MSIL_Balamid_A_2147685071_4
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Balamid.A"
        threat_id = "2147685071"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/reklam/728x90.html" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "chrome" ascii //weight: 1
        $x_1_4 = "safari" ascii //weight: 1
        $x_1_5 = "firefox" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_MSIL_Balamid_A_2147685071_5
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Balamid.A"
        threat_id = "2147685071"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "exec saat" wide //weight: 1
        $x_1_2 = "YaBrowser" wide //weight: 1
        $x_1_3 = "exec uyemckontrol @mac" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = {42 61 73 6c 61 74 5f 43 6c 69 63 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = {44 75 72 64 75 72 5f 43 6c 69 63 6b 00}  //weight: 1, accuracy: High
        $x_1_7 = "/toy.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanClicker_MSIL_Balamid_D_2147721467_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Balamid.D!bit"
        threat_id = "2147721467"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://titiaredh.com/redirect/" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = "htmlfile\\shell\\open\\command" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

