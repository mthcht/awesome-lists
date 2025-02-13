rule Worm_MSIL_Prash_A_2147646437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Prash.A"
        threat_id = "2147646437"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Prash"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 6f 72 6d 53 68 61 72 70 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "net.jajaca.com" wide //weight: 1
        $x_1_3 = "AttackScanner via Gothin, 2011." wide //weight: 1
        $x_1_4 = "Malformed PASV result:" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

