rule Ransom_MSIL_Pryptorc_A_2147689457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Pryptorc.A"
        threat_id = "2147689457"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pryptorc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "documents, etc. were encrypted with ProCrypt-Locker virus." wide //weight: 3
        $x_1_2 = "\\Greeting Card.html" wide //weight: 1
        $x_1_3 = "pageTracker._trackPageview(\\'/clicked/twitter/Tweet_this_Card_Page\\');track_twitter_click" wide //weight: 1
        $x_1_4 = {0b 2a 00 2e 00 62 00 6d 00 70 00 00 0b 2a 00 2e 00 64 00 6f 00 63 00 00 0d 2a 00 2e 00 64 00 6f 00 63 00 78 00 00}  //weight: 1, accuracy: High
        $x_1_5 = {3c 00 21 00 2d 00 2d 00 52 00 45 00 41 00 44 00 20 00 4d 00 45 00 2d 00 2d 00 21 00 [0-8] 49 00 4d 00 50 00 4f 00 52 00 54 00 41 00 4e 00 54 00 3a 00 20 00 44 00 6f 00 20 00 6e 00 6f 00 74 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 74 00 68 00 69 00 73 00 20 00 66 00 69 00 6c 00 65 00 20 00 62 00 65 00 63 00 61 00 75 00 73 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

