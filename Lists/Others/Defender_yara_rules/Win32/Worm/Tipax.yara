rule Worm_Win32_Tipax_A_2147617878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Tipax.A"
        threat_id = "2147617878"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Tipax"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "orland\\Delphi\\RTL" ascii //weight: 10
        $x_1_2 = "3EE549F1B2A0423EF5943E82DF11D535C8E07A940B8253DD46BECE366CEFC0AA9F206B9605755CC79D57E233D88D50" ascii //weight: 1
        $x_1_3 = "1117958A2F81E8E04C20768E44F8A028DD9551D02F22C1D7289C" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

