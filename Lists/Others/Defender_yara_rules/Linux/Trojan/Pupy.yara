rule Trojan_Linux_Pupy_A_2147781114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Pupy.A!MTB"
        threat_id = "2147781114"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Pupy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pupy" ascii //weight: 1
        $x_1_2 = {8b bc 24 18 21 00 00 48 8b 74 24 20 48 8d 15 92 93 00 00 e8 [0-5] 3c ff 75 8b 48 8d 3d 8c 93 00 00 48 8d ac 24 40 10 00 00 e8 [0-5] 48 8d 35 7c 93 00 00 48 89 ef e8 [0-5] 48 85 c0 74 1d e8 [0-5] 48 8d 15 01 8d 00 00 89 c1 be 00 10 00 00 48 89 ef 31 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Pupy_B_2147821036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Pupy.B!MTB"
        threat_id = "2147821036"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Pupy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 01 3c 09 0f 94 c2 3c 20 0f 94 c0 08 c2 75 ?? 48 89 e0 45 31 c9 c6 84 24 00 11 00 00 00 48 8d 14 38 29 d6 44 8d 04 0e 49 63 d0 48 8d 3c 10}  //weight: 1, accuracy: Low
        $x_1_2 = {88 8c 3c 90 21 00 00 48 ff c7 8a 0e 48 ff c6 80 f9 09 0f 95 c2 80 f9 20 0f 95 c0 84 d0 75 e1 41 8d 34 38 48 63 c7 c6 84 04 90 21 00 00 00 48 63 fe 48 8d 0c 3c eb 03}  //weight: 1, accuracy: High
        $x_1_3 = {48 83 ca ff 48 89 c6 31 c0 fc 48 89 d1 48 89 f7 89 d5 f2 ae 48 f7 d1 48 01 d1 49 39 cf 0f 82 [0-5] 4c 89 f7 e8 [0-5] 4c 89 f7 e8 [0-5] 85 c0 89 c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Linux_Pupy_C_2147919020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Pupy.C!MTB"
        threat_id = "2147919020"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Pupy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reflective_inject_dll" ascii //weight: 1
        $x_1_2 = "get_pupy_config" ascii //weight: 1
        $x_1_3 = "linux-inject" ascii //weight: 1
        $x_1_4 = "pupy.error" ascii //weight: 1
        $x_1_5 = "injectSharedLibrary" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

