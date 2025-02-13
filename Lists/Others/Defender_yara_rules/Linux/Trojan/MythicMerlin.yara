rule Trojan_Linux_MythicMerlin_A_2147831417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/MythicMerlin.A"
        threat_id = "2147831417"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "MythicMerlin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {b8 04 00 00 00 48 8d ?? ?? ?? ?? ?? b9 2c 00 00 00 e8 ?? ?? ?? ff 48 8b 94 24 d0 00 00 00 48 8b 82 c0 00 00 00 48 8b 9a c8 00 00 00 48 8b 8a d0 00 00 00 e8 ?? ?? ?? ff [0-2] 48 85 c9 0f 85 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_2 = {48 89 94 24 a8 00 00 00 48 89 84 24 b0 00 00 00 48 8d ?? ?? ?? ?? ?? bb 0e 00 00 00 48 8d [0-6] bf 01 00 00 00 48 89 fe e8 ?? ?? ?? ff 48 89 d9 48 89 c3 b8 04 00 00 00 e8 ?? ?? ?? ff c6 44 24 3f 00 48 8b 8c 24 f8 00 00 00 48 89 ca 48 83 e1 0f}  //weight: 2, accuracy: Low
        $x_2_3 = {48 83 fb 03 75 ?? 66 81 38 6a 61 75 ?? 80 78 02 33 75 ?? 48 8b 4c 24 48 48 8b 81 98 00 00 00 48 8b 99 a0 00 00 00 48 8b 6c 24 38 48 83 c4 40 c3}  //weight: 2, accuracy: Low
        $x_2_4 = {48 81 78 10 c8 00 00 00 0f 85 ?? ?? 00 00 48 8b 58 40 48 8b 48 48 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ff e8 ?? ?? ?? ff 48 85 ff 74 ?? 44 0f 11 bc 24 c0 01 00 00 74 ?? 48 8b 7f 08}  //weight: 2, accuracy: Low
        $x_1_5 = "mythic.PostResponse" ascii //weight: 1
        $x_1_6 = "mythic.Task" ascii //weight: 1
        $x_1_7 = "mythic.Client" ascii //weight: 1
        $x_1_8 = "mythic.Config" ascii //weight: 1
        $x_1_9 = "mythic.CheckIn" ascii //weight: 1
        $x_1_10 = "mythic.RSARequest" ascii //weight: 1
        $x_1_11 = "mythic.RSAResponse" ascii //weight: 1
        $x_1_12 = "mythic.FileDownload" ascii //weight: 1
        $x_1_13 = "jobs.Shellcode" ascii //weight: 1
        $x_1_14 = "jobs.FileTransfer" ascii //weight: 1
        $x_1_15 = "MerlinClient" ascii //weight: 1
        $x_1_16 = "MythicID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

