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
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_12_1 = "RIVATOR" ascii //weight: 12
        $x_2_2 = "Tokens" ascii //weight: 2
        $x_2_3 = {74 65 6c 65 67 72 61 6d 2e 6f 72 67 2f 62 6f 74 [0-80] 73 65 6e 64 4d 65 73 73 61 67 65}  //weight: 2, accuracy: Low
        $x_1_4 = "encrypted_key" ascii //weight: 1
        $x_2_5 = "CheckRemoteDebuggerPresent" ascii //weight: 2
        $x_2_6 = "browserPath" ascii //weight: 2
        $x_2_7 = "**PC:**" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_12_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

