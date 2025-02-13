rule Ransom_MacOS_EvilQuest_YA_2147760454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/EvilQuest.YA!MTB"
        threat_id = "2147760454"
        type = "Ransom"
        platform = "MacOS: "
        family = "EvilQuest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "libtpyrc/tpyrc.c" ascii //weight: 1
        $x_1_2 = {55 48 89 e5 48 83 ec 30 48 89 7d f0 48 c7 45 e8 00 00 00 00 48 8b 7d f0 48 8b 45 f0 48 89 7d d8 48 89 c7 e8 f4 23 00 00 48 8b 15 31 34 00 00 48 8b 7d d8 48 89 c6 48 8d 4d e8 e8 61 20 00 00 48 89 45 e0 48 83 7d e0 00 0f 85 0d 00 00 00 48 8b 45 f0 48 89 45 f8 e9 08 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MacOS_EvilQuest_YB_2147764055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/EvilQuest.YB!MTB"
        threat_id = "2147764055"
        type = "Ransom"
        platform = "MacOS: "
        family = "EvilQuest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/e/toidievitceffe/libtpyrc/tpyrc.c" ascii //weight: 1
        $x_1_2 = "EI_LOCKFILE_DIR" ascii //weight: 1
        $x_1_3 = "EI_CONST_RTG_GAINEDROOT" ascii //weight: 1
        $x_1_4 = "EI_PLIST_CONTENTS" ascii //weight: 1
        $x_1_5 = "EI_TEMP_WAS_UPDATED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MacOS_EvilQuest_B_2147773702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/EvilQuest.B!MTB"
        threat_id = "2147773702"
        type = "Ransom"
        platform = "MacOS: "
        family = "EvilQuest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 7d f0 48 8d 05 fb 45 01 00 48 89 bd e8 fe ff ff 48 89 c7 e8 [0-4] 48 8b bd e8 fe ff ff 48 89 c6 e8 [0-4] 48 89 85 30 ff ff ff 48 83 bd 30 ff ff ff 00 0f 84 [0-4] 48 8b bd 30 ff ff ff e8 [0-4] 83 f8 00 0f}  //weight: 2, accuracy: Low
        $x_2_2 = {c0 89 c6 48 8b bd 30 ff ff ff ba 02 00 00 00 e8 [0-4] 48 8b bd 30 ff ff ff 89 85 e4 fe ff ff e8 [0-4] 31 c9 89 ce 31 d2 48 89 45 d0 48 8b bd 30 ff ff ff e8 [0-4] 48 83 7d d0 00 0f 87 [0-4] 48 8b bd 30 ff ff ff e8 [0-4] 48 8b bd 30 ff ff ff e8 [0-4] c7 45 fc fd ff ff ff e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MacOS_EvilQuest_C_2147828522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/EvilQuest.C!MTB"
        threat_id = "2147828522"
        type = "Ransom"
        platform = "MacOS: "
        family = "EvilQuest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "XY345N5s#p$(<d6HjaKvt!DL+Maiy]-0;amP5Be" ascii //weight: 1
        $x_1_2 = {c0 89 c6 48 8b bd 30 ff ff ff ba 02 00 00 00 e8 [0-4] 48 8b bd 30 ff ff ff 89 85 e4 fe ff ff e8 [0-4] 31 c9 89 ce 31 d2 48 89 45 d0 48 8b bd 30 ff ff ff e8 [0-4] 48 83 7d d0 00 0f 87 [0-4] 48 8b bd 30 ff ff ff e8 [0-4] 48 8b bd 30 ff ff ff e8 [0-4] c7 45 fc fd ff ff ff e9}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 e5 48 83 ec 10 48 89 7d f8 bf 05 00 00 00 48 8d 35 c8 ff ff ff e8 7f 67 01 00 cc 83 3d 27 c0 01 00 00 0f 85 1b 00 00 00 48 8d 3d be 78 01 00 31 c0 e8 0f 67 01 00 bf 33 00 00 00 89 45 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Ransom_MacOS_EvilQuest_A_2147833277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/EvilQuest.A!MTB"
        threat_id = "2147833277"
        type = "Ransom"
        platform = "MacOS: "
        family = "EvilQuest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EI_TEMP_WAS_UPDATED" ascii //weight: 1
        $x_1_2 = "EI_ULD_DIRECTORY" ascii //weight: 1
        $x_1_3 = {d3 db e2 68 27 2e 02 51 42 44 d9 2c 25 3a 32 f9 f4 b5 9e dc 21 80 14 50 ef 13 e0 06 40 f3 11 83 2f d9 bb fa 43 47 2c 17 0c 40 42 c1 82 62 1c 19 e8 97}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MacOS_EvilQuest_D_2147923769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MacOS/EvilQuest.D!MTB"
        threat_id = "2147923769"
        type = "Ransom"
        platform = "MacOS: "
        family = "EvilQuest"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 7d e4 04 0f 8d 3e 00 00 00 48 8b 45 f8 48 63 4d e4 0f b6 14 08 83 fa 00 0f 84 16 00 00 00 48 8b 45 f8 48 63 4d e4 8a 14 08 48 8b 45 e8 48 63 4d e4 88 14 08 e9 00 00 00 00 8b 45 e4 83 c0 01 89 45 e4 e9 b8 ff ff ff 48 8b 45 e8 48 83 c4 20 5d}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 7d e8 00 0f 86 67 00 00 00 48 8b 45 e8 48 25 01 00 00 00 48 83 f8 01 0f 85 21 00 00 00 48 8b 45 d8 48 0f af 45 d0 8b 4d e4 89 ca 31 c9 48 89 55 c8 89 ca 48 8b 75 c8 48 f7 f6 48 89 55 d8 48 8b 45 e8 48 c1 e8 01 48 89 45 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

