rule Trojan_MacOS_Lador_B_2147828865_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Lador.B!MTB"
        threat_id = "2147828865"
        type = "Trojan"
        platform = "MacOS: "
        family = "Lador"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 83 ec 28 48 89 6c 24 20 48 8d 6c 24 20 65 48 8b 04 25 30 00 00 00 48 8b 40 30 83 b8 0c 01 00 00 00 0f 8f a3 00 00 00 80 3d 96 a0 64 00 00 0f 84 8c 00 00 00 48 8b 44 24 30 48 85 c0 75 31 0f 57 c0 0f 11 44 24 10 48 8d 0d 52 d1 02 00 48 89 4c 24 10 48 89 44 24 18 48 8d 44 24 10 48 89 04 24 e8 4a e9 02 00 48 8b 6c 24 20 48 83 c4 28 c3 48 89 04 24 48 8b 4c 24 38 48 89 4c 24 08 e8 9d b3 fd ff 80 3d 3a a0 64 00 00 74 07 48 8b 44 24 30}  //weight: 2, accuracy: High
        $x_2_2 = {65 48 8b 0c 25 30 00 00 00 48 3b 61 10 0f 86 61 01 00 00 48 83 ec 30 48 89 6c 24 28 48 8d 6c 24 28 48 83 3d 37 82 63 00 00 0f 84 2a 01 00 00 48 8b 44 24 38 0f 57 c0 f2 48 0f 2a c0 f2 0f 59 05 b4 4a 65 00 f2 0f 11 44 24 20 48 8d 05 07 82 63 00 48 89 04 24 e8 26 ba fe ff f2 0f 10 44 24 20 f2 48 0f 2c c0}  //weight: 2, accuracy: High
        $x_1_3 = "IOPlatformExpertDevice" ascii //weight: 1
        $x_1_4 = "github.com/denisbrodbeck/machineid.extractID" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_Lador_C_2147923950_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Lador.C!MTB"
        threat_id = "2147923950"
        type = "Trojan"
        platform = "MacOS: "
        family = "Lador"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 89 fb e8 e2 e0 2e 00 48 89 03 8b 35 2b c7 4b 00 8b 3d 29 c7 4b 00 85 ff 75 25 48 83 ec 10 48 89 e7 e8 c9 e0 2e 00 8b 34 24 8b 7c 24 04 48 83 c4 10 89 35 04 c7 4b 00 89 f8 87 05 00 c7 4b 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 48 8b 0c 25 30 00 00 00 48 3b 61 10 76 43 48 83 ec 28 48 89 6c 24 20 48 8d 6c 24 20 48 8b 44 24 30 48 89 04 24 48 8b 44 24 38 48 89 44 24 08 48 c7 44 24 10 0c 00 00 00 e8 82 d6 fa ff 48 8b 44 24 18 48 89 44 24 40 48 8b 6c 24 20 48 83 c4 28 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_Lador_D_2147933249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Lador.D!MTB"
        threat_id = "2147933249"
        type = "Trojan"
        platform = "MacOS: "
        family = "Lador"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 89 fb e8 64 70 38 00 48 89 03 8b 35 fb d7 57 00 8b 3d f9 d7 57 00 85 ff 75 25 48 83 ec 10 48 89 e7 e8 4b 70 38 00 8b 34 24 8b 7c 24 04 48 83 c4 10 89 35 d4 d7 57 00 89 f8 87 05 d0 d7 57 00 89 73 08 89 7b 0c 48 89 ec 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 ec 28 48 89 1c 24 4c 89 64 24 08 4c 89 6c 24 10 4c 89 74 24 18 4c 89 7c 24 20 48 8b 17 65 48 89 14 25 30 00 00 00 fc e8 d2 f1 fc ff 48 8b 1c 24 4c 8b 64 24 08 4c 8b 6c 24 10 4c 8b 74 24 18 4c 8b 7c 24 20 31 c0 48 83 c4 28 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

