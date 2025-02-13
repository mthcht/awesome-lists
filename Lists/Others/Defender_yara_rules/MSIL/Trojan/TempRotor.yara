rule Trojan_MSIL_TempRotor_A_2147835388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TempRotor.A!dha"
        threat_id = "2147835388"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TempRotor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {06 6b 27 14 8a ac ba 41 a7 0b 95 78 18 43 a9 e4}  //weight: 100, accuracy: High
        $x_100_2 = {9f 2a e2 60 86 28 ed 46 8f fa a0 80 bf 10 5d cf}  //weight: 100, accuracy: High
        $x_100_3 = {3d 5d cd c1 f4 53 5d 45 87 02 38 4d 49 45 37 bd}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_TempRotor_E_2147835389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TempRotor.E!dha"
        threat_id = "2147835389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TempRotor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {53 65 74 43 6f 6e 66 69 67 00 53 65 6e 64 00 47 65 74 43 6f 6e 66 69 67}  //weight: 100, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_TempRotor_F_2147835390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/TempRotor.F!dha"
        threat_id = "2147835390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "TempRotor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "300"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "kHvswGyvj7A15EYbQQqbiscgBY4UmLwReh0Fs/nfNfwB" ascii //weight: 100
        $x_100_2 = "K.DefaultStorage.key" ascii //weight: 100
        $x_100_3 = "K.DefaultStorage.bin" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

