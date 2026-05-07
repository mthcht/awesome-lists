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

