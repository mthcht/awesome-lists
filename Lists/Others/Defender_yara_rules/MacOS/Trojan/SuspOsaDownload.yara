rule Trojan_MacOS_SuspOsaDownload_A_2147958584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspOsaDownload.A"
        threat_id = "2147958584"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspOsaDownload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "https://%@/dynamic?txd=%@" ascii //weight: 2
        $x_2_2 = "Downloaded AppleScript source:" ascii //weight: 2
        $x_1_3 = "api-key" ascii //weight: 1
        $x_1_4 = "/tmp/test.scpt" ascii //weight: 1
        $x_1_5 = "https://%@/gate" ascii //weight: 1
        $x_1_6 = "----WebKitFormBoundary7MA4YWxkTrZu0gW" ascii //weight: 1
        $x_1_7 = "/tmp/osalogging.zip" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MacOS_SuspOsaDownload_B_2147959556_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SuspOsaDownload.B"
        threat_id = "2147959556"
        type = "Trojan"
        platform = "MacOS: "
        family = "SuspOsaDownload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "killall Terminal" ascii //weight: 2
        $x_2_2 = {3c 6b 65 79 3e 52 75 6e 41 74 4c 6f 61 64 3c 2f 6b 65 79 3e [0-32] 3c 74 72 75 65 2f 3e}  //weight: 2, accuracy: Low
        $x_2_3 = "<string>/usr/bin/osascript</string>" ascii //weight: 2
        $x_2_4 = "do shell script \"curl -s https://t.me" ascii //weight: 2
        $x_2_5 = "/api.php?check=" ascii //weight: 2
        $x_2_6 = "get.php?oid=" ascii //weight: 2
        $x_2_7 = " | osascript" ascii //weight: 2
        $x_1_8 = "launchctl load %s/com." ascii //weight: 1
        $x_1_9 = "launchctl load ~/Library/LaunchAgents/com." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

