rule Trojan_Linux_Reptile_A_2147849292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Reptile.A"
        threat_id = "2147849292"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Reptile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "custom_rol32" ascii //weight: 1
        $x_1_2 = "do_encode" ascii //weight: 1
        $x_1_3 = "reptile_blob" ascii //weight: 1
        $x_1_4 = {4f ec c4 4e [0-4] 89 [0-3] c1 ?? 02 89 ?? 01 ?? 01 ?? c1 ?? 02 01 ?? 29 ?? 89 ?? (8b|89) [0-8] (33|31)}  //weight: 1, accuracy: Low
        $x_4_5 = {2f 72 65 70 74 69 6c 65 2f 72 65 70 74 69 6c 65 5f 63 6d 64 ?? 66 69 6c 65 2d 74 61 6d 70 65 72 69 6e 67}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Reptile_B_2147849293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Reptile.B"
        threat_id = "2147849293"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Reptile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/reptile/reptile_shell" ascii //weight: 1
        $x_1_2 = "/reptile/reptile_start" ascii //weight: 1
        $x_1_3 = "name=reptile_module" ascii //weight: 1
        $x_1_4 = "hax0r" ascii //weight: 1
        $x_1_5 = "s3cr3t" ascii //weight: 1
        $x_1_6 = "#<reptile>" ascii //weight: 1
        $x_1_7 = "#</reptile>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Linux_Reptile_C_2147849294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Reptile.C"
        threat_id = "2147849294"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Reptile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d8 31 d2 89 df 41 f7 f0 81 f7 ?? ?? ?? ?? 83 eb 04 88 d1 d3 c7 31 3e 48 83 c6 04 83 fb ?? 75 df}  //weight: 2, accuracy: Low
        $x_2_2 = {89 f0 31 d2 41 89 f0 41 f7 f1 41 81 f0 ?? ?? ?? ?? 83 ee 04 88 d1 41 d3 c0 44 31 07 48 83 c7 04 83 fe 04 75 db}  //weight: 2, accuracy: Low
        $x_2_3 = {44 89 c8 31 d2 29 f0 89 c7 41 f7 f0 81 f7 ?? ?? ?? ?? ?? ?? d3 c7 31 be ?? ?? ?? ?? 48 83 c6 04 48 81 fe ?? ?? ?? ?? 75 d7}  //weight: 2, accuracy: Low
        $x_10_4 = "parasite_blob" ascii //weight: 10
        $x_1_5 = "kallsyms_on_each_symbol" ascii //weight: 1
        $x_1_6 = "ksym_lookup_cb" ascii //weight: 1
        $x_1_7 = "init_module" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Reptile_D_2147849295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Reptile.D"
        threat_id = "2147849295"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Reptile"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1b 5b 30 31 c7 ?? 04 3b 33 32 6d c7 ?? 08 53 75 63 63 c7 ?? 0c 65 73 73 21 c7 ?? 10 1b 5b 30 30 c7 ?? 14 6d 0a 00 00}  //weight: 5, accuracy: Low
        $x_5_2 = {1b 5b 30 30 c7 ?? 04 3b 33 31 6d c7 ?? 08 59 6f 75 20 c7 ?? 0c 68 61 76 65 c7 ?? 10 20 6e 6f 20 c7 ?? 14 70 6f 77 65 c7 ?? 18 72 20 68 65 c7 ?? 1c 72 65 21 20 c7 ?? 20 3a 28 20 1b c7 ?? 24 5b 30 30 6d c7 ?? 28 0a 0a 00 00}  //weight: 5, accuracy: Low
        $x_5_3 = {1b 5b 30 31 c7 ?? 04 3b 33 36 6d c7 ?? 08 59 6f 75 20 c7 ?? 0c 67 6f 74 20 c7 ?? 10 73 75 70 65 c7 ?? 14 72 20 70 6f c7 ?? 18 77 65 72 73 c7 ?? 1c 21 1b 5b 30 c7 ?? 20 30 6d 0a 0a c7 ?? 24 00 00 00 00}  //weight: 5, accuracy: Low
        $x_5_4 = {59 6f 75 20 c7 ?? 04 61 72 65 20 c7 ?? 08 61 6c 72 65 c7 ?? 0c 61 64 79 20 c7 ?? 10 72 6f 6f 74 c7 ?? 14 21 20 3a 29 c7 ?? 18 0a 0a 00 00}  //weight: 5, accuracy: Low
        $x_1_5 = "[01;36mYou got super powers!" ascii //weight: 1
        $x_1_6 = "[00;31mYou have no power here!" ascii //weight: 1
        $x_1_7 = "[01;32mSuccess!" ascii //weight: 1
        $x_1_8 = "[01;31mFailed!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 2 of ($x_1_*))) or
            ((4 of ($x_5_*))) or
            (all of ($x*))
        )
}

