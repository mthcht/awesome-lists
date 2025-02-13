rule Trojan_Linux_Merlin_A_2147831418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Merlin.A"
        threat_id = "2147831418"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Merlin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 83 fb 05 0f 85 ?? ?? ?? ?? 8b 08 81 f9 68 74 74 70 0f 85 ?? ?? ?? ?? 80 78 04 33 74 ?? 81 f9 68 74 74 70 e9}  //weight: 2, accuracy: Low
        $x_2_2 = {80 78 04 73 0f 85 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ff 48 c7 40 08 08 00 00 00 48 8d ?? ?? ?? ?? ?? 48 89 08 48 8b 4c 24 48 48 c7 41 70 01 00 00 00 48 c7 41 78 01 00 00 00}  //weight: 2, accuracy: Low
        $x_2_3 = {49 81 f8 c8 00 00 00 0f 84 ?? ?? ?? ?? 49 81 f8 91 01 00 00 0f 85 ?? ?? ?? ?? b8 02 00 00 00 48 8d ?? ?? ?? ?? ?? b9 4f 00 00 00 e8 ?? ?? ?? ff 48 8d}  //weight: 2, accuracy: Low
        $x_2_4 = {48 83 fb 0a 75 ?? 48 b9 70 61 64 64 69 6e 67 6d [0-1] 48 39 08 75 ?? 66 81 78 08 61 78 75 ?? 48 8b 4c 24 48 48 8b 81 a0 00 00 00 bb 0a 00 00 00}  //weight: 2, accuracy: Low
        $x_2_5 = {48 8b 6d 00 48 89 d8 48 89 cb e8 ?? ?? ?? ff [0-2] 48 83 fb 06 0f 85 ?? ?? ?? ?? 81 38 6f 70 61 71 0f 85 ?? ?? ?? ?? 66 81 78 04 75 65}  //weight: 2, accuracy: Low
        $x_1_6 = "jobs.Shellcode" ascii //weight: 1
        $x_1_7 = "mythic.CheckIn" ascii //weight: 1
        $x_1_8 = "mythic.Client" ascii //weight: 1
        $x_1_9 = "mythic.Config" ascii //weight: 1
        $x_1_10 = "mythic.Response" ascii //weight: 1
        $x_1_11 = "github.com/Ne0nd0g/merlin" ascii //weight: 1
        $x_1_12 = "github.com/Ne0nd0g/ja3transport" ascii //weight: 1
        $x_1_13 = "MerlinClient" ascii //weight: 1
        $x_1_14 = "MythicID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

