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

