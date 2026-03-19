rule Trojan_MSIL_FsocietyRAT_AMTB_2147964799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FsocietyRAT!AMTB"
        threat_id = "2147964799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FsocietyRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {46 73 6f 63 69 65 74 79 52 41 54 5f 43 6c 69 65 6e 74 2e 46 73 6f 63 69 65 74 79 41 67 65 6e 74 2b 3c [0-31] 3e}  //weight: 2, accuracy: Low
        $x_1_2 = "Diego Fsociety RAT.pdb" ascii //weight: 1
        $x_1_3 = "Cookie stealing requires additional libraries" ascii //weight: 1
        $x_2_4 = "FSOCIETY WAS HERE" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

