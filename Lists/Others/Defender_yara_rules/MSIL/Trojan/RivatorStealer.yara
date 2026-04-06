rule Trojan_MSIL_RivatorStealer_A_2147962351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RivatorStealer.A!AMTB"
        threat_id = "2147962351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RivatorStealer"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "efzeezfefzefr.exe" ascii //weight: 5
        $x_5_2 = "RIVATOR" ascii //weight: 5
        $x_5_3 = {74 00 65 00 6c 00 65 00 67 00 72 00 61 00 6d 00 2e 00 6f 00 72 00 67 00 2f 00 62 00 6f 00 74 00 [0-144] 73 00 65 00 6e 00 64 00 4d 00 65 00 73 00 73 00 61 00 67 00 65 00}  //weight: 5, accuracy: Low
        $x_5_4 = {74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 [0-144] 73 65 6e 64 4d 65 73 73 61 67 65}  //weight: 5, accuracy: Low
        $x_1_5 = "encrypted_key" ascii //weight: 1
        $x_1_6 = "**PC:**" ascii //weight: 1
        $x_1_7 = "Tokens:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

