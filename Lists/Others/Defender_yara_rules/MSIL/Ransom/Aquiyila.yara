rule Ransom_MSIL_Aquiyila_A_2147705696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Aquiyila.A"
        threat_id = "2147705696"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Aquiyila"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Everything Set! Virus fully activated" ascii //weight: 1
        $x_1_2 = "see your computer explode!!! NOBODY CAN DELETE THIS" ascii //weight: 1
        $x_1_3 = "Computer destroyed succesfully, rebooting to finish process" ascii //weight: 1
        $x_1_4 = "enter the key and re-use your computer" ascii //weight: 1
        $x_1_5 = "COMPUTER DESTROYED, YOU BETTER PAYED THE FEE, see you next time" ascii //weight: 1
        $x_2_6 = "://satoshibox.com/5578e40712fb6d9f028b45a1" ascii //weight: 2
        $x_10_7 = "C:\\Users\\Owner\\Desktop\\TOR ransomware\\Ransomware 2.0\\obj\\Debug\\TOR_DEALER_CUSTOM1.pdb" ascii //weight: 10
        $x_10_8 = "Bassmonster68@safe-mail.net" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

