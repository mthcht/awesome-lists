rule Backdoor_MacOS_NetWired_2147740672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/NetWired"
        threat_id = "2147740672"
        type = "Backdoor"
        platform = "MacOS: "
        family = "NetWired"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "checkip.dyndns.org" ascii //weight: 2
        $x_2_2 = "machdep.cpu.brand_string" ascii //weight: 2
        $x_4_3 = {42 0f b6 d2 0f b6 44 14 08 01 c3 0f b6 db 8a 4c 1c 08 88 4c 14 08 88 44 1c 08 00 c1 0f b6 c1 8a 44 04 08 30 07 47 4e 75 d7 a1 1c e0 00 00 8b 00 3b 84 24 08 01 00 00 75 0b 81 c4 0c 01 00 00 5e 5f 5b 5d c3}  //weight: 4, accuracy: High
        $x_1_4 = "RunAtLoad" ascii //weight: 1
        $x_1_5 = "/Library/LaunchAgents/" ascii //weight: 1
        $x_1_6 = "CONNECT %s:%d HTTP/1.0" ascii //weight: 1
        $x_1_7 = "hyd7u5jdi8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MacOS_NetWired_A_2147741085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/NetWired.A"
        threat_id = "2147741085"
        type = "Backdoor"
        platform = "MacOS: "
        family = "NetWired"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 44 24 14 bd 64 00 00 00 0f b6 04 08 0f af c7 83 c0 32 99 f7 fd 85 c0 74 0f ba ff 00 00 00 3d 00 01 00 00 0f 4c d0 eb 05 ba 01 00 00 00 0f b6 04 0e 41 8b 6c 24 1c 83 f9 40 88 54 05 00 75 c0 5b 5e 5f 5d c3}  //weight: 5, accuracy: High
        $x_1_2 = "Library/Application Support/Firefox" ascii //weight: 1
        $x_1_3 = "Library/Application Support/Thunderbird" ascii //weight: 1
        $x_1_4 = "/Library/Opera/wand.dat" ascii //weight: 1
        $x_1_5 = "Library/Application Support/SeaMonkey" ascii //weight: 1
        $x_1_6 = "/signons.sqlite" ascii //weight: 1
        $x_1_7 = "PK11_GetInternalKeySlot" ascii //weight: 1
        $x_1_8 = "PK11SDR_Decrypt" ascii //weight: 1
        $x_1_9 = "sqlite3_prepare_v2" ascii //weight: 1
        $x_1_10 = "machdep.cpu.brand_string" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

