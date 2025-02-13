rule Trojan_MSIL_Balamid_A_2147685079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Balamid.A"
        threat_id = "2147685079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.wintask16.com/url.txt" ascii //weight: 1
        $x_1_2 = "user_pref(\"browser.startup.homepage\"" ascii //weight: 1
        $x_1_3 = "\"startup_urls\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Balamid_A_2147685079_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Balamid.A"
        threat_id = "2147685079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.wintask32.com/url.txt" ascii //weight: 1
        $x_1_2 = "user_pref(\"browser.startup.homepage\"" ascii //weight: 1
        $x_1_3 = "\"startup_urls\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Balamid_A_2147685079_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Balamid.A"
        threat_id = "2147685079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.wintask64.com/url.txt" ascii //weight: 1
        $x_1_2 = "user_pref(\"browser.startup.homepage\"" ascii //weight: 1
        $x_1_3 = "\"urls_to_restore_on_startup\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Balamid_A_2147685079_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Balamid.A"
        threat_id = "2147685079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Balamid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "baglanmadi" ascii //weight: 10
        $x_10_2 = "/exc2.txt" ascii //weight: 10
        $x_10_3 = "\\lsm.exe" ascii //weight: 10
        $x_1_4 = {77 77 77 2e 77 69 6e 74 61 73 6b 03 00 2e 63 6f 6d}  //weight: 1, accuracy: Low
        $x_1_5 = {77 00 77 00 77 00 2e 00 77 00 69 00 6e 00 74 00 61 00 73 00 6b 00 01 00 00 01 00 00 01 00 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

