rule Trojan_Win32_Scribroz_A_2147650358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scribroz.A"
        threat_id = "2147650358"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scribroz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "7131947146573746B736277677D1517521204161B52" wide //weight: 4
        $x_4_2 = "626556475C444118665D56545D" wide //weight: 4
        $x_2_3 = "565840655041455A585F6A6C48465D7D595957" wide //weight: 2
        $x_2_4 = "50435B5141585A5C545F6947765A465D42464A" wide //weight: 2
        $x_1_5 = "054E04020C" wide //weight: 1
        $x_1_6 = "5444524046554557501B50575C185A4A" wide //weight: 1
        $x_1_7 = "5959455A050D5A43411B5B5C57445D5D1D5C5B" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

