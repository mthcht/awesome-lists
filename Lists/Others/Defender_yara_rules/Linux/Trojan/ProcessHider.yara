rule Trojan_Linux_ProcessHider_A_2147756253_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ProcessHider.A!MTB"
        threat_id = "2147756253"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ProcessHider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hide_tcp_ports" ascii //weight: 1
        $x_1_2 = "/app/is_hidden_file.c" ascii //weight: 1
        $x_1_3 = "is_attacker" ascii //weight: 1
        $x_1_4 = "get_process_name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Linux_ProcessHider_B_2147798312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ProcessHider.B!MTB"
        threat_id = "2147798312"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ProcessHider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 48 81 ec 20 02 00 00 48 89 bd e8 fd ff ff 48 8b 05 13 2d 00 00 48 85 c0 75 4c 48 8d 35 ac 0c 00 00 48 c7 c7 ff ff ff ff e8 43 fd ff ff 48 89 05 f4 2c 00 00 48 8b 05 ed 2c 00 00 48 85 c0 75 26 e8 3b fd ff ff 48 89 c2 48 8b 05 39 2c 00 00 48 8b 00 48 8d 35 7e 0c 00 00 48 89 c7 b8 00 00 00 00 e8 da fc ff ff 48 8b 15 bb 2c 00 00 48 8b 85 e8 fd ff ff 48 89 c7 ff d2 48 89 45 f8 48 83 7d f8 00 74 7c 48 8d 8d f0 fd ff ff 48 8b 85 e8 fd ff ff ba 00 01 00 00 48 89 ce 48 89 c7 e8 b3 fd ff ff 85 c0 74 5a 48 8d 85 f0 fd ff ff 48 8d 35 37 0c 00 00 48 89 c7 e8 64 fc ff ff 85 c0 75 40 48 8b 45 f8 48 8d 50 13 48 8d 85 f0 fe ff ff 48 89 c6 48 89 d7 e8 0b fe ff ff 85 c0 74 22 48 8b 15 33 2c 00 00 48 8d 85 f0 fe ff ff 48 89 d6 48 89 c7 e8 29 fc ff ff 85 c0 75 05}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 fc 48 8d 45 b0 89 d1 48 8d 15 01 0e 00 00 be 40 00 00 00 48 89 c7 b8 00 00 00 00 e8 49 fe ff ff 48 8b 55 98 48 8b 4d a0 48 8d 45 b0 48 89 ce 48 89 c7 e8 02 fe ff ff 48 89 45 f0 48 83 7d f0 ff 75 07 b8 00 00 00 00 eb 13 48 8b 55 f0}  //weight: 1, accuracy: High
        $x_1_3 = "xmrig" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_ProcessHider_C_2147819195_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ProcessHider.C!MTB"
        threat_id = "2147819195"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ProcessHider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 15 90 29 00 00 48 8d 85 f0 fe ff ff 48 89 d6 48 89 c7 e8 7e fa ff ff 85 c0 75 05 e9 5d ff ff ff 90 48 8b 85 e8 fd ff ff 48 8b 4d f8 64 48 33 0c 25 28 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 95 d8 fe ff ff 48 8d 85 e0 fe ff ff be 00 01 00 00 48 89 c7 e8 39 fd ff ff 48 85 c0 75 16 48 8b 85 d8 fe ff ff 48 89 c7 e8 d5 fc ff ff b8 00 00 00 00 eb 3d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_ProcessHider_C_2147819195_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ProcessHider.C!MTB"
        threat_id = "2147819195"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ProcessHider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {78 61 5f 66 69 6e 61 6c 69 7a 65 00 5f 4a 76 5f 52 65 67 69 73 74 65 72 43 6c 61 73 73 65 73 00 64 69 72 66 64 00 73 6e 70 72 69 6e 74 66 00 72 65 61 64 6c 69 6e 6b 00 73 74 72 73 70 6e 00 73 74 72 6c 65 6e 00 66 6f 70 65 6e 00 66 67 65 74 73 00 66 63 6c 6f 73 65 00 73 73 63 61 6e 66 00 72 65 61 64 64 69 72 36 34 00 64 6c 73 79 6d 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 00 66 70 72 69 6e 74 66 00 73 74 72 63 6d 70 00 72 65 61 64 64 69 72 00 6c 69 62 64 6c 2e 73 6f 2e 32 00 6c 69 62 63 2e 73 6f 2e 36 00 5f 65 64 61 74 61 00 5f 5f 62 73 73 5f 73 74 61 72 74 00 5f}  //weight: 1, accuracy: High
        $x_1_3 = "get_process_name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_ProcessHider_D_2147923834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ProcessHider.D!MTB"
        threat_id = "2147923834"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ProcessHider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 41 54 53 48 83 ec 10 89 7d ec 48 89 75 e0 48 8b 45 e0 48 8b 00 48 89 c7 e8 48 fa ff ff 48 8b 45 e0 48 8d 58 08 48 8b 55 e0 8b 45 ec 48 89 d6 89 c7 e8 73 fb ff ff 48 89 03 48 8b 45 e0 48 83 c0 08 48 8b 00 48 85 c0 74 0a 48 8b 45 e0 4c 8b 60 08}  //weight: 1, accuracy: High
        $x_1_2 = {83 7b 08 25 48 8b 2b 0f 85 b2 01 00 00 ff 53 10 48 83 c3 18 48 89 45 00 48 81 fb b0 02 40 00 72 df e8 72 05 00 00 48 8b 05 9b 02 2c 00 48 85 c0 0f 84 93 01 00 00 48 8b 10 48 89 d6 48 89 54 24 20 40 80 e6 00 64 48 89 34 25 28 00 00 00 48 85 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_ProcessHider_SR7_2147950248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ProcessHider.SR7"
        threat_id = "2147950248"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ProcessHider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hide_demo" ascii //weight: 2
        $x_2_2 = "/proc/self/fd/%d" ascii //weight: 2
        $x_2_3 = "/proc/%s/stat" ascii //weight: 2
        $x_2_4 = "process_to_filter" ascii //weight: 2
        $x_2_5 = "original_readdir" ascii //weight: 2
        $x_2_6 = "get_dir_name" ascii //weight: 2
        $x_2_7 = "get_process_name" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_ProcessHider_SR21_2147950262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ProcessHider.SR21"
        threat_id = "2147950262"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ProcessHider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "insmod " wide //weight: 2
        $x_10_2 = "rootkit.ko" wide //weight: 10
        $x_10_3 = "diamorphine.ko" wide //weight: 10
        $x_10_4 = "rtkkeylogger.ko" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Linux_ProcessHider_E_2147951882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ProcessHider.E!MTB"
        threat_id = "2147951882"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ProcessHider"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.checkMinerInHiddenLocations" ascii //weight: 1
        $x_1_2 = "main.addToLdPreload" ascii //weight: 1
        $x_1_3 = "main.checkAndLaunchMiner" ascii //weight: 1
        $x_1_4 = "main.prepareAndLaunchMiner" ascii //weight: 1
        $x_1_5 = "main.prepareTools" ascii //weight: 1
        $x_1_6 = "main.launchMinerWithRandomName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

