rule Trojan_MacOS_AmosStealer_PA_2147920372_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealer.PA!MTB"
        threat_id = "2147920372"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "2d2d646174612d62696e61727920402f746d702f6f75742e7a697020687474703a2f2f37392e3133372e3139322e342f7032702229" ascii //weight: 3
        $x_1_2 = "73657420726573756c745f73656e6420746f2028646f207368656c6c2073637269707420226375726c202d5820504f5354202d48205c22757569643a20" ascii //weight: 1
        $x_1_3 = "2f746d702f7875796e612f46696c65477261626265722f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AmosStealer_GAV_2147965805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealer.GAV!MTB"
        threat_id = "2147965805"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_14_1 = {29 f7 40 88 3c 11 48 ff c2 48 83 c0 0c 48 83 fa 0c 0f 84 13 01 00 00 8b 70 fc 8d 3c 76 33 78 f8 0f b6 08 d3 ff f6 85 [0-5] 4c 89 e9 74 cf}  //weight: 14, accuracy: Low
        $x_1_2 = "curl -s -X POST -H 'Content-Type: application/json' -d @- '" ascii //weight: 1
        $x_1_3 = "> /dev/null 2>&1" ascii //weight: 1
        $x_1_4 = "curl -s -m 30 '" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AmosStealer_GAV_2147965805_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealer.GAV!MTB"
        threat_id = "2147965805"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_14_1 = {48 8b 95 38 ff ff ff 48 ff c1 48 39 d1 73 24 4c 89 fa a8 01 75 07 48 8b 95 40 ff ff ff 30 1c 0a 0f b6 95 30 ff ff ff f6 c2 01 0f 94 c0 75 d1}  //weight: 14, accuracy: High
        $x_1_2 = "_usleep" ascii //weight: 1
        $x_1_3 = "_waitpid" ascii //weight: 1
        $x_1_4 = "_write" ascii //weight: 1
        $x_1_5 = "dyld_stub_binder" ascii //weight: 1
        $x_1_6 = "radr://5614542" ascii //weight: 1
        $x_1_7 = "execl" ascii //weight: 1
        $x_1_8 = "execvp" ascii //weight: 1
        $x_1_9 = "fork" ascii //weight: 1
        $x_1_10 = "memcpy" ascii //weight: 1
        $x_1_11 = "memmove" ascii //weight: 1
        $x_1_12 = "-iLd" ascii //weight: 1
        $x_1_13 = "?W5/=\\" ascii //weight: 1
        $x_1_14 = "/+ub-%" ascii //weight: 1
        $x_1_15 = "/bin/zsh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((14 of ($x_1_*))) or
            ((1 of ($x_14_*))) or
            (all of ($x*))
        )
}

rule Trojan_MacOS_AmosStealer_DA_2147968389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealer.DA!MTB"
        threat_id = "2147968389"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/ws/terminal/bot" ascii //weight: 1
        $x_1_2 = "curl -s -X POST -H 'Content-Type: application/js" ascii //weight: 1
        $x_1_3 = "/dev/null 2>" ascii //weight: 1
        $x_1_4 = "curl -s -m 30" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AmosStealer_MU_2147968567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealer.MU!MTB"
        threat_id = "2147968567"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Shell terminated" ascii //weight: 1
        $x_1_2 = "/ws/terminal/bot" ascii //weight: 1
        $x_1_3 = "curl -s -X POST -H 'Content-Type: application/js" ascii //weight: 1
        $x_1_4 = "/dev/null 2>" ascii //weight: 1
        $x_1_5 = "curl -s -m 30" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AmosStealer_MU_2147968567_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealer.MU!MTB"
        threat_id = "2147968567"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "curl " wide //weight: 2
        $x_2_2 = "-kfsSL" wide //weight: 2
        $x_2_3 = "/curl/" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_AmosStealer_DB_2147972240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealer.DB!MTB"
        threat_id = "2147972240"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 6d 34 70 61 74 68 38 66 69 6c 65 6e 61 6d 65 42 38 6e 65 32 30 30 31 30 30 45 76 00 5f 5f 5a 4e 53 74 33 5f 5f 31 34 5f 5f 66 73 31 30 66 69 6c 65 73 79 73 74 65 6d 64 76 42 38 6e 65 32 30 30 31 30 30 45 52 4b 4e 53 31 5f 34 70 61 74 68 45 53 34 5f 00 5f 5f 5a 4e 53 74 33 5f 5f 31 34 5f 5f 66 73 31 30 66}  //weight: 1, accuracy: High
        $x_1_2 = {6e 67 49 54 5f 54 30 5f 54 31 5f 45 45 50 4b 53 36 5f 4f 53 39 5f 00 5f 5f 5a 4e 53 74 33 5f 5f 31 34 5f 5f 66 73 31 30 66 69 6c 65 73 79 73 74 65 6d 34 70 61 74 68 43 32 42 38 6e 65 32 30 30 31 30 30 49 50 63 76 45 45 52 4b 54 5f 4e 53 32 5f 36 66 6f 72 6d 61 74 45 00 5f 5f 5a 4e 53 74 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MacOS_AmosStealer_DC_2147977093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/AmosStealer.DC!MTB"
        threat_id = "2147977093"
        type = "Trojan"
        platform = "MacOS: "
        family = "AmosStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 95 86 38 c6 ec 8b 49 bf ef 2a 34 f3 b6 96 ff 1d ad 0c d8 73 48 d4 72 26 21 c6 d1 62 3e 5d 4e f0 54 2a f0 f9 b1 1c d6 c9 91 a8 c0 a1 33 92 d2 a0 a6 0e e9 75 21 d2 b6 6a 75 8f 91 98 fe 78 e1 2d 4f 3b 60 83 b4 f2 74 7b be 56 0e 97 f4 30 24 c7 cb c6 ec a1 bb 7e 9a 00 62}  //weight: 1, accuracy: High
        $x_1_2 = {52 29 e6 1f 58 29 f6 63 56 29 f4 4f 55 29 e1 17 53 29 f7 37 59 29 4e 01 80 52 ef 47 57 29 10 02 19 0b c6 00 10 4a c6 40 86 13 d6 00 16 0b d9 02 19 4a 39 53 99 13 30 03 10 0b 06 02 06 4a da 60 86 13 00 00 15 0b e6 00 00 4a c6 40 86 13 c7 00 18 0b f5 00 15 4a b8 52 95 13 00 03 00 0b 06 00 06 4a c6 60 86 13 d5 00 07 0b a7 02 18 4a e7 64 87 13 21 00 14 0b f7 02 01 4a f7 42 97}  //weight: 1, accuracy: High
        $x_1_3 = {7e ad 9b 29 34 a9 9b 69 24 aa 9b 8a fd 5a d3 8c 65 00 12 8d 38 a8 9b 4d 34 ab 9b aa 41 2a 8b 4d fd 5a d3 4a 65 00 12 4e 3c a8 9b 0e 38 ab 9b cd 41 2d 8b ae fd 5a d3 b7 65 00 12 0d 40 a8 9b ad 36 ab 9b ad 41 2e 8b ae fd 5a d3 b4 65 00 12 a8 26 a8 9b 68 22 ab 9b 08 41 2e 8b 09 fd 5a d3 16 65 00 12 28 09 09 0b 08 01 0c 0b 19 65 00 12 58 69 48 0b 7b 03 1c 8b 5a 03 1c eb 61 f5 ff 54 06}  //weight: 1, accuracy: High
        $x_1_4 = {53 6c 12 00 39 0c 00 0f 0b ae 7d 10 53 6e 16 00 39 ae 7d 08 53 6e 1a 00 39 6d 1e 00 39 4d 7d 18 53 6d 22 00 39 4d 7d 10 53 6d 26 00 39 4d 7d 08 53 6d 2a 00 39 6a 2e 00 39 2a 7d 18 53 6a 32 00 39 2a 7d 10 53 6a 36 00 39 2a 7d 08 53 6a 3a 00 39 69 3e 00 39 69 7d 18 53 69 42 00 39 69 7d 10 53 69 46 00 39 69 7d 08 53 69 4a 00 39 6b 4e 00 39 09 7d 18 53 69 52 00 39 09 7d 10 53 69 56 00 39 09 7d 08 53 69 5a 00 39}  //weight: 1, accuracy: High
        $x_1_5 = {01 66 0f 3a 22 d1 02 66 0f 3a 22 d2 03 66 0f fe d1 f3 0f 7f 17 66 0f 6e c8 66 41 0f 3a 22 ca 01 66 41 0f 3a 22 c8 02 66 0f 3a 22 ce 03 66 0f fe c8 f3 0f 7f 4f 10 48 81 c4}  //weight: 1, accuracy: High
        $x_1_6 = {6e 74 00 90 00 73 18 12 40 5f 4f 53 41 44 69 73 70 6f 73 65 00 90 00 73 20 12 40 5f 4f 53 41 45 78 65 63 75 74 65 00 90 00 73 28 12 40 5f 4f 53 41 4c 6f 61 64 00 90 00 73 30 15 40 5f 4f 70 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

