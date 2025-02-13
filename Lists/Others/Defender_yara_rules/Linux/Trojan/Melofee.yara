rule Trojan_Linux_Melofee_B_2147844327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Melofee.B!MTB"
        threat_id = "2147844327"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Melofee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/sbin/rmmod %s" ascii //weight: 1
        $x_1_2 = "/sbin/insmod %s" ascii //weight: 1
        $x_1_3 = "rm -fr /etc/rc.modules" ascii //weight: 1
        $x_1_4 = "/etc/intel_audio/audio | xargs kill 2>/dev/null" ascii //weight: 1
        $x_2_5 = {55 48 89 e5 48 83 ec 30 48 89 7d e8 48 89 75 e0 89 55 dc 48 8b 45 e8 ba ed 01 00 00 be 41 02 00 00 48 89 c7 b8 00 00 00 00 e8 ?? ?? ?? ?? 89 45 fc 83 7d fc 00 79 07 b8 ff ff ff ff eb 26 8b 45 dc 48 63 d0 48 8b 4d e0 8b 45 fc 48 89 ce 89 c7 e8 ?? ?? ?? ?? 8b 45 fc 89 c7 e8}  //weight: 2, accuracy: Low
        $x_2_6 = {8b 45 a8 89 c2 48 8b 4d d8 8b 45 e4 48 89 ce 89 c7 e8 ?? ?? ?? ?? 8b 45 e4 89 c7 e8 ?? ?? ?? ?? 48 8d 45 a0 48 89 c7 e8 ?? ?? ?? ?? 48 89 c2 48 8d 85 c0 f8 ff ff be b4 1e 40 00 48 89 c7 b8 00 00 00 00 e8 ?? ?? ?? ?? 48 8d 85 c0 f8 ff ff 48 89 c7 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 45 e8}  //weight: 2, accuracy: Low
        $x_2_7 = {83 7d e8 00 75 ?? c7 45 ec 03 00 00 00 eb 0e 8b 45 ec 89 c7 e8 ?? ?? ?? ?? 83 45 ec 01 81 7d ec fe 00 00 00 0f 9e c0 84 c0 75 ?? be 00 00 00 00 bf 4a 1d 40 00 e8 ?? ?? ?? ?? bf 01 00 00 00 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_Melofee_A_2147844752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Melofee.A!MTB"
        threat_id = "2147844752"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Melofee"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 6e ac 03 77 8b ae 56 7c a7 d6 24 e1 82 ec 31 e0 9f b9 f9 27 5a 8a e4 80 d7 60 5b 00 5f d3 1a 88 a9 49 4d 1d b7 c0 aa 4f 3e cc 20 99 a9 a7 fb 4e 5f 73 4a 6c 45 e1 e8 0e ac 3d 59 71 6d 20 c1 b9 18 3c d8 d4 7e 6d ba 5c 9c 63 bd c5 ab 1d d7 5b 38 5b 74 9b 99 95 b6 d0 9d 48 da 21 3f ae 40}  //weight: 1, accuracy: High
        $x_1_2 = {5b 22 ce 1f 6b 8a 5d b3 85 ca be ec 23 0a 7e 31 c7 67 42 73 f1 28 bf 34 0f 32 40 55 6e 6b f0 25 8e 6e f7 f4 f9 31 d1 c4 cd df f3 f7 18 bb a0 d2 a6 d9 51 be 28 86 a8 bf 74 f4 58 2c 82 e1 0b ff c3 68 fc 40 33 62 27 65 0d ae 53 15 6b 09 53 ea 0c cd c8 61 51 01 ab 8d 4e 57 3a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

