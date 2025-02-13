rule TrojanSpy_Win32_Hisbucken_A_2147650209_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hisbucken.A"
        threat_id = "2147650209"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hisbucken"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "8584641424479196947464730021E584A525" wide //weight: 4
        $x_4_2 = "58584641424479196947464730021E584A52" wide //weight: 4
        $x_4_3 = "SOURCE=KRAKEN;UID=sa;DATABASE=kraken;PWD=sa" wide //weight: 4
        $x_2_4 = "90637D7366600264036C7C5920435F435656" wide //weight: 2
        $x_2_5 = "125E5D58577E07" wide //weight: 2
        $x_2_6 = "8445D455D" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_2_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            ((3 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Hisbucken_B_2147659396_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hisbucken.B"
        threat_id = "2147659396"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hisbucken"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "55"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "ccjclassificados.com" wide //weight: 20
        $x_20_2 = "form_j_tancode_SUBMIT" wide //weight: 20
        $x_10_3 = "BC54B076ABAD68A279C85BAC" wide //weight: 10
        $x_5_4 = "1D0EF73CD24CC65FA7BA6EBC59E320F54D" wide //weight: 5
        $x_5_5 = "44D434CD5DBF5DB743DE34C940C64A" wide //weight: 5
        $x_5_6 = "32EA28F425F218F64CC040CC" wide //weight: 5
        $x_5_7 = "E23FDF2BE07BA77C8C6ABB889C68B8" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_20_*) and 3 of ($x_5_*))) or
            ((2 of ($x_20_*) and 1 of ($x_10_*) and 1 of ($x_5_*))) or
            (all of ($x*))
        )
}

