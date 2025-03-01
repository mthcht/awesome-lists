rule Trojan_MSIL_Screenlock_Adv_2147728910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Screenlock.Adv"
        threat_id = "2147728910"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Screenlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_8_1 = "Advanced Ransi\\Advanced Ransi\\obj\\Debug\\Advanced Ransi.pdb" ascii //weight: 8
        $x_8_2 = "Your Computer Got Sniped by AcroWare Cryptolocker!" ascii //weight: 8
        $x_8_3 = "Advanced_Ransi." ascii //weight: 8
        $x_8_4 = "Advanced Ransi.exe" ascii //weight: 8
        $x_4_5 = "72 Hours till your data will be lost" ascii //weight: 4
        $x_4_6 = "Already have the decryption key" ascii //weight: 4
        $x_4_7 = "YOUR COMPUTER GOT LOCKED" ascii //weight: 4
        $x_1_8 = "Decrypt!" ascii //weight: 1
        $x_1_9 = "https://bitpay.com/pay-with-bitcoin" ascii //weight: 1
        $x_1_10 = "Wrong Code!" ascii //weight: 1
        $x_1_11 = "Hours Left" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((1 of ($x_8_*) and 2 of ($x_4_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}

