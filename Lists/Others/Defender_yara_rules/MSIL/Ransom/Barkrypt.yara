rule Ransom_MSIL_Barkrypt_A_2147726533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Barkrypt.A"
        threat_id = "2147726533"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barkrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_ransom" ascii //weight: 1
        $x_1_2 = "set_ransom" ascii //weight: 1
        $x_1_3 = "get_accHax" ascii //weight: 1
        $x_1_4 = "set_accHax" ascii //weight: 1
        $x_1_5 = "get_decrypt" ascii //weight: 1
        $x_1_6 = "set_decrypt" ascii //weight: 1
        $x_1_7 = "get_emailHax" ascii //weight: 1
        $x_1_8 = "set_emailHax" ascii //weight: 1
        $x_1_9 = "get_ipHaxer" ascii //weight: 1
        $x_1_10 = "set_ipHaxer" ascii //weight: 1
        $x_1_11 = "hackerBoi" ascii //weight: 1
        $x_1_12 = "Your files will be lost  in 6hrs" ascii //weight: 1
        $x_1_13 = "HAXERBOI RANSOM" ascii //weight: 1
        $x_1_14 = "OOPS YOUR FILES HAVE BEEN" ascii //weight: 1
        $x_1_15 = "Hack Goverment" ascii //weight: 1
        $x_1_16 = "choose a country, before hacking" ascii //weight: 1
        $x_1_17 = "Cracking Firewall" ascii //weight: 1
        $x_1_18 = "Making Russian Bots" ascii //weight: 1
        $x_1_19 = "Deleting Important Emails" ascii //weight: 1
        $x_1_20 = "Injecting RansomWare" ascii //weight: 1
        $x_1_21 = "Getting Bank Accounts" ascii //weight: 1
        $x_1_22 = "Deleting Microsoft Office 365" ascii //weight: 1
        $x_1_23 = "Finishing Up" ascii //weight: 1
        $x_1_24 = "Hacked" ascii //weight: 1
        $x_10_25 = "1J8fviYFZ4Kaz3CCnSos5zbMtPUX9PwpGd" ascii //weight: 10
        $x_10_26 = "hackerBoi\\hackerBoi\\obj\\Debug\\hackerBoi.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((15 of ($x_1_*))) or
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

