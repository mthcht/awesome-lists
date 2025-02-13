rule Ransom_MacOS_Filecoder_YA_2147758575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Filecoder.YA!MTB"
        threat_id = "2147758575"
        type = "Ransom"
        platform = "MacOS: "
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 e5 48 83 ec 20 48 89 7d f8 c7 45 f4 00 00 00 00 48 8b 7d f8 48 c7 c6 fc ff ff ff ba 02 00 00 00 e8 7e 14 00 00 48 8d 75 f4 48 8b 4d f8 48 89 f7 be 01 00 00 00 ba 04 00 00 00 89 45 f0 e8 55 14 00 00 45 31 c0 44 89 c6 31 d2 48 8b 7d f8 48 89 45 e8 e8 4c 14 00 00 81 7d f4 be ba be dd 41 0f 94 c1 41 80 e1 01 41 0f b6 d1 89 45 e4 89 d0 48 83 c4 20 5d c3}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 7d c0 48 8b 45 c0 48 89 bd 78 ff ff ff 48 89 c7 e8 78 f9 00 00 48 8b 4d b8 48 8b bd 78 ff ff ff be 01 00 00 00 48 89 c2 e8 94 f8 00 00 48 89 45 b0 48 8b 7d b8 e8 81 f8 00 00 48 8b 7d b8 e8 48 f8 00 00 48 8b 7d c0 89 85 74 ff ff ff e8 51 f8 00 00 48 8b 4d b0 48 8b 7d c0 48 89 8d 68 ff ff ff e8 27 f9 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "toidievitceffe/libpersist/rennur.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_MacOS_Filecoder_YB_2147759369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Filecoder.YB!MTB"
        threat_id = "2147759369"
        type = "Ransom"
        platform = "MacOS: "
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "toidievitceffe/libpersist/rennur.c" ascii //weight: 1
        $x_1_2 = "/toidievitceffe/libpersist/persist.c" ascii //weight: 1
        $x_1_3 = "ei_rootgainer_elevate" ascii //weight: 1
        $x_1_4 = "INFECTOR MAIN" ascii //weight: 1
        $x_1_5 = "get_process_list" ascii //weight: 1
        $x_1_6 = "carver_main" ascii //weight: 1
        $x_1_7 = "virtual_mchn" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MacOS_Filecoder_YC_2147761694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Filecoder.YC!MTB"
        threat_id = "2147761694"
        type = "Ransom"
        platform = "MacOS: "
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/toidievitceffe/libpersist/rennur.c" ascii //weight: 1
        $x_1_2 = "/libtpyrc/tpyrc.c" ascii //weight: 1
        $x_1_3 = "/toidievitceffe/libpersist/persist.c" ascii //weight: 1
        $x_1_4 = "INFECTOR MAIN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MacOS_Filecoder_A_2147817558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Filecoder.A!xp"
        threat_id = "2147817558"
        type = "Ransom"
        platform = "MacOS: "
        family = "Filecoder"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "README.txt" ascii //weight: 1
        $x_1_2 = "{}.crypt" ascii //weight: 1
        $x_1_3 = "201002130000" ascii //weight: 1
        $x_1_4 = " rihofoj@zainmax.net" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MacOS_Filecoder_YD_2147923773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/Filecoder.YD!MTB"
        threat_id = "2147923773"
        type = "Ransom"
        platform = "MacOS: "
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 05 bb f1 88 00 48 85 c0 74 60 48 8d 35 df f3 ff ff 48 c7 c2 00 00 00 00 48 c7 c1 00 00 00 00 ff d0 48 8d 0d 08 56 8d 00 48 8b 01 48 05 a0 03 00 00 48 89 41 10 48 89 41 18}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 f8 48 89 f3 48 83 ec 28 48 83 e4 f0 48 89 44 24 18 48 89 5c 24 20 48 8d 3d 81 56 8d 00 48 8d 9c 24 00 00 ff ff 48 89 5f 10 48 89 5f 18 48 89 1f 48 89 67 08 b8 00 00 00 00 0f a2 83 f8 00 74 2c 81 fb 47 65 6e 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

