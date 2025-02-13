rule Trojan_MacOS_Shlayer_B_2147818374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Shlayer.B"
        threat_id = "2147818374"
        type = "Trojan"
        platform = "MacOS: "
        family = "Shlayer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Denis Safronov1" ascii //weight: 1
        $x_1_2 = "B3TKG9PKF31" ascii //weight: 1
        $x_2_3 = {0f b6 0c 01 48 8b 55 ?? 2a 4c 02 ?? 88 4d ff 0f b6 4d ff 48 8b 55 f0 88 4c 15 ea 48 ff 45 ?? 48 8b 4d ?? 48 83 f9 ?? 76 d3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

