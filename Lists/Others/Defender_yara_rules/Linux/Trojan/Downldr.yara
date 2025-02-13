rule Trojan_Linux_Downldr_A_2147788467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Downldr.A!xp"
        threat_id = "2147788467"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Downldr"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xmrig" ascii //weight: 1
        $x_1_2 = {65 63 68 6f 20 27 2a 20 2a 20 2a 20 2a 20 2a 20 65 63 68 6f 20 2d 6e [0-5] 7c 20 62 61 73 65 36 34 20 2d 64 20 7c 73 68 20 3e 20 2f 64 65 76 2f 6e 75 6c 6c 20 32 3e 26 31 27 20 7c 20 63 72 6f 6e 74 61 62}  //weight: 1, accuracy: Low
        $x_1_3 = "initrd.target" ascii //weight: 1
        $x_1_4 = "network.target" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

