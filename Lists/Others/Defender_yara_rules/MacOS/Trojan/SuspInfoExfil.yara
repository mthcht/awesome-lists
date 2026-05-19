rule Trojan_MacOS_SuspInfoExfil_C_2147969675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspInfoExfil.C"
        threat_id = "2147969675"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspInfoExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "curl -s" wide //weight: 1
        $x_1_2 = " POST " wide //weight: 1
        $x_1_3 = "/api/bot/heartbeat -H Content-Type" wide //weight: 1
        $x_1_4 = "bot_id" wide //weight: 1
        $x_1_5 = "hostname" wide //weight: 1
        $x_1_6 = "os_version" wide //weight: 1
        $x_1_7 = "build_id" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SuspInfoExfil_D_2147969676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspInfoExfil.D"
        threat_id = "2147969676"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspInfoExfil"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "curl -s -X POST" wide //weight: 10
        $x_10_2 = "/api/debug/event -H Content-Type" wide //weight: 10
        $x_5_3 = "event" wide //weight: 5
        $x_5_4 = "build_hash" wide //weight: 5
        $x_1_5 = "payload_started" wide //weight: 1
        $x_1_6 = "collecting_wallet" wide //weight: 1
        $x_1_7 = "password_obtained" wide //weight: 1
        $x_1_8 = "zip_sent" wide //weight: 1
        $x_1_9 = "collecting_browser" wide //weight: 1
        $x_1_10 = "loader_requested" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_5_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

