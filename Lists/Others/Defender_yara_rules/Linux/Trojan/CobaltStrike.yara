rule Trojan_Linux_CobaltStrike_C_2147853500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CobaltStrike.C!MTB"
        threat_id = "2147853500"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {27 86 71 8e 60 be 67 1d 41 73 25 df 04 df 68 49 da 1c 6d 38 30 81 f1 ca fc f3 07 1c 16 b0 5f 3f f6 92 46 2c 01 bd 86 93 c0 c5 66 83}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_CobaltStrike_B_2147853501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CobaltStrike.B!MTB"
        threat_id = "2147853501"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6e 64 09 70 73 20 2d 61 75 78 0a 00 2f 70 3e 63 00 6f 70 65 28 ef ff ac fd 69 72 20 66}  //weight: 10, accuracy: High
        $x_5_2 = "Geacon/core.REVERSE" ascii //weight: 5
        $x_5_3 = ".PWD" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_CobaltStrike_D_2147890165_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CobaltStrike.D!MTB"
        threat_id = "2147890165"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {51 0c 7c 62 2f dd d6 2a 37 8d 7e 68 54 c0 2f aa 8b dd 47 37 a8 b1 38 56 fc 62 b8 c8 dd 97 d7 7a 0b a7 57 2f a6 8b 0c dd 2a ff a1 98 4c b8 c8 c0 5a 59 dd 3e a7 7b 91 81 4f a5 32 a2 5c dd 17 0e 37 5c 64 e0 13 d0 24 17 66 dd cb c8 c0 27 2a bf c3 08}  //weight: 1, accuracy: High
        $x_1_2 = {45 43 e8 89 8a d3 41 61 98 0d 40 bf 31 f8 70 87 81 c0 9d 28 45 fb 36 1c 14 9c 5e b6 01 1d f0 82 92 31 d2 85 bd 0f 09 69 6f 2b ca a5 61 3d be 92 52 83 80 b7 17 ca 40 b5 78 74 0f 76 90 50 d3 0e 28 a0 75 40 da 08}  //weight: 1, accuracy: High
        $x_1_3 = {4e 44 08 7d 60 f9 a2 19 7d 04 96 f1 c0 2a 4f a0 22 2e 52 a7 63 b0 c5 21 a4 3e 01 61 34 7d 42 02 61 1c 33 5b e1 5c 02 1e 7e 59 15 13 b0 82 13 71 eb e0 03 39 3a 83 a0 81 60 a5 b8 5f 10 d8 44 cc}  //weight: 1, accuracy: High
        $x_1_4 = {31 4b 17 fd 9b c7 36 dc 79 4f 4c c2 25 57 bc 08 db 36 d8 e1 13 a1 70 ba d7 c0 99 10 61 f7 44 f4 13 fe 37 e4 34 3f 16 2e 4e 36 9d 38 81 97 d0 cd df 0f 07 85 9e 27 e4 e5 36 cc 8e 45 6d 92 b0 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_CobaltStrike_G_2147929994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CobaltStrike.G!MTB"
        threat_id = "2147929994"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crypt/config_decrypt.go" ascii //weight: 1
        $x_1_2 = "packet/commands_linux.go" ascii //weight: 1
        $x_1_3 = "services.CmdDownload" ascii //weight: 1
        $x_1_4 = "services.CmdSleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_CobaltStrike_H_2147937784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CobaltStrike.H!MTB"
        threat_id = "2147937784"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 30 fd 99 00 55 48 81 ee 30 fd 99 00 48 89 e5 48 c1 fe 03 48 89 f0 48 c1 e8 3f 48 01 c6 48 d1 fe 74 15 b8 00 00 00 00 48 85 c0 74 0b 5d bf 30 fd 99 00 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {44 88 cb f6 c3 01 0f 94 47 f0 41 83 ea 0a 0f 9c 42 f0 8a 5f f0 44 8a 72 f0 44 20 f3 44 8a 77 f0 44 8a 7a f0 45 30 fe 44 08 f3 80 e3 01 88 58 f0 48 89 e0 48 83 c0 f0 48 89 c4 c7 00 ee 5d 15 26 48 83 ec 0a 50 68 93 45 41 1d 31 c0 0f 84 01 00 00 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_CobaltStrike_I_2147951877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/CobaltStrike.I!MTB"
        threat_id = "2147951877"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "CobaltStrike"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main/command.parseCommandUpload" ascii //weight: 1
        $x_1_2 = "main/command.portForwardServe" ascii //weight: 1
        $x_1_3 = "main/packet.PullCommand" ascii //weight: 1
        $x_1_4 = "/command/port_forward.go" ascii //weight: 1
        $x_1_5 = "main/command.parseCommandShell" ascii //weight: 1
        $x_1_6 = "main/command.Upload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

