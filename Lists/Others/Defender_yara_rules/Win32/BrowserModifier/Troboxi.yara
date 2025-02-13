rule BrowserModifier_Win32_Troboxi_A_176175_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Troboxi.A"
        threat_id = "176175"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Troboxi"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f b7 c0 0f b7 c9 c1 e0 10 0b c1 0f b6 4d ?? 0b c6 31 45 ec 0f b6 45 ?? 33 c1 33 c6 06 00 8a 65 ?? 8a 6d}  //weight: 3, accuracy: Low
        $x_1_2 = "2099569420" ascii //weight: 1
        $x_1_3 = "search?q={searchTerms}&clid=1" ascii //weight: 1
        $x_1_4 = "%s?param=%s&aid=%s" ascii //weight: 1
        $x_1_5 = "user_pref(\"keyword.URL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule BrowserModifier_Win32_Troboxi_196738_0
{
    meta:
        author = "defender2yara"
        detection_name = "BrowserModifier:Win32/Troboxi"
        threat_id = "196738"
        type = "BrowserModifier"
        platform = "Win32: Windows 32-bit platform"
        family = "Troboxi"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "110"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = ")551{nn*432o34n(/%$9" ascii //weight: 10
        $x_5_2 = "http://kurs.ru/index" ascii //weight: 5
        $x_5_3 = "176.9.157.143/counter" ascii //weight: 5
        $x_100_4 = {59 50 6a 01 6a 00 8d 45 d8 50 e8 ?? ?? 00 00 59 50 ff 75 a8 ff 15 ?? ?? 40 00 ff 75 a8 ff 15 ?? ?? 40 00 5f 5e 5b c9 c3}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_5_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

