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

rule Trojan_MacOS_Shlayer_SA_2147964636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Shlayer.SA"
        threat_id = "2147964636"
        type = "Trojan"
        platform = "MacOS: "
        family = "Shlayer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 00 61 00 69 00 6c 00 20 00 2d 00 63 00 20 00 [0-96] 2e 00 61 00 70 00 70 00 2f 00 43 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 73 00 2f 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 6d 00 61 00 69 00 6e 00 2e 00 70 00 6e 00 67 00 [0-16] 6f 00 70 00 65 00 6e 00 73 00 73 00 6c 00 20 00 65 00 6e 00 63 00 20 00 2d 00 61 00 65 00 73 00 2d 00 32 00 35 00 36 00 2d 00 63 00 62 00 63 00 20 00 2d 00 73 00 61 00 6c 00 74 00 20 00 2d 00 6d 00 64 00 20 00 6d 00 64 00 35 00 20 00 2d 00 64 00 20 00 2d 00 41 00 20 00 2d 00 62 00 61 00 73 00 65 00 36 00 34 00 20 00 2d 00 6f 00 75 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6f 00 70 00 65 00 6e 00 73 00 73 00 6c 00 20 00 65 00 6e 00 63 00 20 00 2d 00 62 00 61 00 73 00 65 00 36 00 34 00 20 00 2d 00 64 00 20 00 2d 00 61 00 65 00 73 00 2d 00 32 00 35 00 36 00 2d 00 63 00 62 00 63 00 20 00 2d 00 6e 00 6f 00 73 00 61 00 6c 00 74 00 20 00 2d 00 70 00 61 00 73 00 73 00 20 00 70 00 61 00 73 00 73 00 3a 00 [0-48] 3c 00 [0-21] 2f 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 65 00 6e 00 63 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

