rule TrojanProxy_Win32_Ditsolay_B_2147684902_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Ditsolay.B"
        threat_id = "2147684902"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Ditsolay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "325"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "D21EBF60E16989CA0456E172ED21D67EDB0136A0C7022BD0005A87CF1521B35586B" ascii //weight: 100
        $x_100_2 = "3DA82AD67EC564E779E373E571A254F355F82EB83E9840ED65FD5BFB61ED6E9347F" ascii //weight: 100
        $x_100_3 = "6984C16ED77FA327B82332A23EF127AE28CD016FF16E99B91DA7234AB469E2173DE" ascii //weight: 100
        $x_25_4 = "C531924780D57ADF7DDA0B47A344E0" ascii //weight: 25
        $x_25_5 = "58A134EC7BD97ED2036180DB" ascii //weight: 25
        $x_25_6 = "D02AAD64E61ACA085AF51F4DA7B2" ascii //weight: 25
        $x_25_7 = "82E606339832DD7BE873FB5C" ascii //weight: 25
        $x_25_8 = "E106619624BD69E472F87DDF" ascii //weight: 25
        $x_25_9 = "C51AB86DE77EB2D1084D" ascii //weight: 25
        $x_25_10 = "3298CF024C8BBE1B7DDB0C4282BAAE17A654FA" ascii //weight: 25
        $x_25_11 = "02489F52FC5C8DC9C302369C2DE75085CC0232A720BB6794CF" ascii //weight: 25
        $x_50_12 = "17B41A399ECD7DDE70E04B54FA21D37F" ascii //weight: 50
        $x_50_13 = "66E3658CCB1BC80A5BF762BD1438EA56" ascii //weight: 50
        $x_50_14 = "68E56B963CAB5FE072EE554E84A85BE6" ascii //weight: 50
        $x_50_15 = "5DEA6C973FAE5CFF5181EB379D42F05C" ascii //weight: 50
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_50_*) and 7 of ($x_25_*))) or
            ((4 of ($x_50_*) and 5 of ($x_25_*))) or
            ((1 of ($x_100_*) and 1 of ($x_50_*) and 7 of ($x_25_*))) or
            ((1 of ($x_100_*) and 2 of ($x_50_*) and 5 of ($x_25_*))) or
            ((1 of ($x_100_*) and 3 of ($x_50_*) and 3 of ($x_25_*))) or
            ((1 of ($x_100_*) and 4 of ($x_50_*) and 1 of ($x_25_*))) or
            ((2 of ($x_100_*) and 5 of ($x_25_*))) or
            ((2 of ($x_100_*) and 1 of ($x_50_*) and 3 of ($x_25_*))) or
            ((2 of ($x_100_*) and 2 of ($x_50_*) and 1 of ($x_25_*))) or
            ((2 of ($x_100_*) and 3 of ($x_50_*))) or
            ((3 of ($x_100_*) and 1 of ($x_25_*))) or
            ((3 of ($x_100_*) and 1 of ($x_50_*))) or
            (all of ($x*))
        )
}

