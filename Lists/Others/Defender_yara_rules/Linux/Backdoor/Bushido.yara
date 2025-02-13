rule Backdoor_Linux_Bushido_A_2147793861_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Bushido.A!xp"
        threat_id = "2147793861"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Bushido"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NiGGeRd0nks1337" ascii //weight: 1
        $x_1_2 = "SO190Ij1X" ascii //weight: 1
        $x_1_3 = "1337SoraLOADER" ascii //weight: 1
        $x_1_4 = "scanx86" ascii //weight: 1
        $x_2_5 = {47 45 54 20 2f 73 68 65 6c 6c 3f 63 64 2b 2f 74 6d 70 3b 2b 77 67 65 74 2b 68 74 74 70 3a 2f 5c 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f [0-16] 2f [0-16] 2e 61 72 6d 3b 2b 63 68 6d 6f 64 2b 37 37 37 2b [0-16] 2e 61 72 6d 3b 2b 2e 2f [0-16] 2e 61 72 6d 20 4a 61 77 73 2e 53 65 6c 66 72 65 70 3b 72 6d 2b 2d 72 66 2b [0-16] 2e 61 72 6d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

