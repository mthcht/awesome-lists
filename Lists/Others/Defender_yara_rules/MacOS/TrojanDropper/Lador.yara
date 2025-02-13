rule TrojanDropper_MacOS_Lador_K_2147832800_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MacOS/Lador.K!MTB"
        threat_id = "2147832800"
        type = "TrojanDropper"
        platform = "MacOS: "
        family = "Lador"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {65 48 8b 0c 25 30 00 00 00 48 3b 61 10 0f 86 e3 03 00 00 48 83 ec 38 48 89 6c 24 30 48 8d 6c 24 30 48 8d 05 98 4d 31 00 48 89 04 24 e8 0f d6 00 00 48 8b 7c 24 08 48 89 7c 24 28 48 8d 35 be ce 3e 00 48 89 6c 24 f0 48 8d 6c 24 f0 e8 eb 8e 06 00 48 8b 6d 00 83 3d 14 89 5e 00 00 0f 1f 40 00 0f 85 70 02 00 00 48 8d 05 34 8d 5e 00 48 8b 4c 24 28 48 89 41 10 48 8d 05 23 8d 5e 00 48 89 41 30 48 8d 05 1a 8d 5e 00 48 89 41 50 48 8d 05 10 8d 5e 00 48 89 41 70 48 8d 05 06 8d 5e 00 48 89 81 90 00 00 00 48 8d 05 f9 8c 5e 00}  //weight: 2, accuracy: High
        $x_2_2 = {49 89 c6 48 89 c7 e8 c1 27 3f 00 be 00 01 00 08 48 89 c7 e8 ba 27 3f 00 48 89 c3 48 ff c3 48 89 df e8 b2 27 3f 00 49 89 c4 b9 00 01 00 08 4c 89 f7 48 89 c6 48 89 da e8 a2 27 3f 00 84 c0 74 1e 48 8b 05 55 48 57 00 48 8b 38 31 c0 48 8d 35 62 dd 3e 00 4c 89 e2 44 89 e9}  //weight: 2, accuracy: High
        $x_1_3 = "denisbrodbeck/machineid.extractid" ascii //weight: 1
        $x_1_4 = "IOPlatformExpertDevice" ascii //weight: 1
        $x_1_5 = "runtime.persistentalloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

