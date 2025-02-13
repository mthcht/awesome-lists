rule PWS_MSIL_Costealer_A_2147728306_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Costealer.A!bit"
        threat_id = "2147728306"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Costealer"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 00 61 00 67 00 64 00 6e 00 73 00 2e 00 63 00 6f 00 6d 00 [0-47] 73 00 74 00 61 00 72 00 74 00 2e 00 70 00 68 00 70 00}  //weight: 10, accuracy: Low
        $x_1_2 = "wallet.dat" wide //weight: 1
        $x_1_3 = "upper.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

