rule Trojan_Linux_Kabypari_2147808230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Kabypari"
        threat_id = "2147808230"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Kabypari"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "linux_rat/src/Client.Sx_url" ascii //weight: 1
        $x_1_2 = "linux_rat/src/g.init" ascii //weight: 1
        $x_1_3 = "linux_rat/src/Client.Did" ascii //weight: 1
        $x_1_4 = "linux_rat/src/Client.U_os" ascii //weight: 1
        $x_1_5 = "linux_rat/src/Client.Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

