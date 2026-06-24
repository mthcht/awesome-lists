rule Trojan_MacOS_Infostealer_A_2147842338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Infostealer.A"
        threat_id = "2147842338"
        type = "Trojan"
        platform = "MacOS: "
        family = "Infostealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "system_profiler SPHardwareDataType >" ascii //weight: 1
        $x_1_2 = "/Library/Application Support/zoom.us/data/zoomus.enc.db" ascii //weight: 1
        $x_1_3 = "/Desktop -maxdepth 1 -name \"*.txt\" >" ascii //weight: 1
        $x_1_4 = "/Documents -maxdepth 1 -name \"*.txt\" >" ascii //weight: 1
        $x_1_5 = "/dev/null find-generic-password -ga 'Chrome'" ascii //weight: 1
        $x_1_6 = "awk '{print $2}' >" ascii //weight: 1
        $x_1_7 = ".txt && rm -Rf" ascii //weight: 1
        $x_1_8 = "userbot=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_MacOS_Infostealer_DA_2147972245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Infostealer.DA!MTB"
        threat_id = "2147972245"
        type = "Trojan"
        platform = "MacOS: "
        family = "Infostealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "23"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mnemonic" ascii //weight: 1
        $x_1_2 = "raw_seed" ascii //weight: 1
        $x_1_3 = "seed_phrase" ascii //weight: 1
        $x_1_4 = "bip39hex_key" ascii //weight: 1
        $x_1_5 = "BEGIN RSA" ascii //weight: 1
        $x_1_6 = "BEGIN PRIVATE" ascii //weight: 1
        $x_1_7 = "BEGIN ENCRYPTED" ascii //weight: 1
        $x_1_8 = "BEGIN OPENSSH " ascii //weight: 1
        $x_1_9 = "kdbx" ascii //weight: 1
        $x_1_10 = ".ssh" ascii //weight: 1
        $x_1_11 = ".env" ascii //weight: 1
        $x_1_12 = "/private/var/db/" ascii //weight: 1
        $x_1_13 = "host-profile" ascii //weight: 1
        $x_1_14 = "sk_live_" ascii //weight: 1
        $x_1_15 = "ghp_" ascii //weight: 1
        $x_1_16 = "xoxb-" ascii //weight: 1
        $x_1_17 = "access_token" ascii //weight: 1
        $x_1_18 = "refresh_token" ascii //weight: 1
        $x_1_19 = "db_password" ascii //weight: 1
        $x_1_20 = "mongodb+srv://" ascii //weight: 1
        $x_1_21 = "postgresql://" ascii //weight: 1
        $x_1_22 = "amqp://" ascii //weight: 1
        $x_1_23 = "smtp://" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

