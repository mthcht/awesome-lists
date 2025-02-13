rule Ransom_AndroidOS_Coravin_A_2147751697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/Coravin.A!ex"
        threat_id = "2147751697"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "Coravin"
        severity = "Critical"
        info = "ex: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 72 64 20 70 61 73 73 00 0a 34 38 36 35 30 38 90}  //weight: 2, accuracy: High
        $x_1_2 = {09 76 65 72 69 66 79 50 69 6e 00 0a 76 65 72 69 66 79 5f 70 69 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {17 42 6c 6f 63 6b 65 64 41 70 70 41 63 74 69 76 69 74 79 2e 6a 61 76 61 00 11 42 6c 6f 63 6b 69 6e 67 20 6f 6e 20 6c 6f 63 6b}  //weight: 1, accuracy: High
        $x_1_4 = {43 6f 6e 67 72 61 74 73 2e 20 59 6f 75 20 50 68 6f 6e 65 20 69 73 20 44 65 63 72 79 70 74 65 64 00}  //weight: 1, accuracy: High
        $x_1_5 = "Decryption Code is Incor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

