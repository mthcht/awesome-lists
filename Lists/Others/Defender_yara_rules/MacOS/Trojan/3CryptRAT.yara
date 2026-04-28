rule Trojan_MacOS_3CryptRAT_A_2147967897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/3CryptRAT.A"
        threat_id = "2147967897"
        type = "Trojan"
        platform = "MacOS: "
        family = "3CryptRAT"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "3Crypt test marker" ascii //weight: 1
        $x_1_2 = "/api/v1/upload" ascii //weight: 1
        $x_1_3 = "pbpaste 2>/dev/null" ascii //weight: 1
        $x_1_4 = "keylog_start" ascii //weight: 1
        $x_1_5 = "lsof -c Safari -c Chrome -c Arc 2>/dev/null" ascii //weight: 1
        $x_1_6 = "bot_id" ascii //weight: 1
        $x_1_7 = "virtualbox" ascii //weight: 1
        $x_1_8 = "PT_DENY_ATTACH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

