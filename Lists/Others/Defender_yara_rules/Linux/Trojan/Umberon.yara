rule Trojan_Linux_Umberon_A_2147773636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Umberon.A!MTB"
        threat_id = "2147773636"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Umberon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "get_hideports" ascii //weight: 1
        $x_1_2 = "get_my_procname" ascii //weight: 1
        $x_1_3 = "reinstall_self" ascii //weight: 1
        $x_2_4 = {75 73 72 2f 73 68 61 72 65 2f 6c 69 62 63 2e 73 6f 2e [0-21] 2e 24 7b 50 4c 41 54 46 4f 52 4d 7d 2e 6c 64 2d 32 2e 32 32 2e 73 6f}  //weight: 2, accuracy: Low
        $x_2_5 = "/etc/ld.so.N1JfTvi" ascii //weight: 2
        $x_1_6 = {48 8b 45 e8 8b 40 08 89 c7 e8 a6 fd ff ff 89 45 e0 48 8b 45 e8 8b 40 04 89 c7 e8 95 fd ff ff 89 45 dc 48 8b 45 f8 0f b7 40 04 0f b7 c0 89 c7 e8 20 fd ff ff 66 89 45 da 81 7d e0 00 c5 00 00 75 2b 81 7d dc c4 00 00 00 75 22 66 81 7d da b1 0f 75 1a 48 8b 45 e8 0f b7 00 0f b7 d0 48 8b 45 f8 8b 40 0c 89 d6 89 c7 e8 97 fe ff ff}  //weight: 1, accuracy: High
        $x_2_7 = {2f 6c 69 62 63 2e 73 6f 2e [0-21] 2f 62 69 6e 2f 65 73 70 65 6f 6e 2d 73 68 65 6c 6c}  //weight: 2, accuracy: Low
        $x_2_8 = "backconnect" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

