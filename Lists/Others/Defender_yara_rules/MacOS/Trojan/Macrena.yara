rule Trojan_MacOS_Macrena_A_2147747956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/Macrena.A!MTB"
        threat_id = "2147747956"
        type = "Trojan"
        platform = "MacOS: "
        family = "Macrena"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MachoMan - roy g biv" ascii //weight: 1
        $x_1_2 = {54 ff 75 e0 56 53 50 33 c0 b0 c4 cd 80 83 f8 00 7e 30 83 c4 14 8d 3c 06 53 56 80 7e 06 08 74 3c 0f b6 46 04 03 f0 3b f7 72 f0 5e 5b 73 d2}  //weight: 1, accuracy: High
        $x_1_3 = {6a 08 56 53 50 6a 03 58 cd 80 83 c4 10 56 ad 91 ad 5e 0f c1 04 24 e2 41 91 0f b1 4c 24 04 75 12 6a 2c 56 53 50 b0 03 cd 80 83 c4 10 83 7e 24 00 75 13}  //weight: 1, accuracy: High
        $x_1_4 = {3d ce fa ed fe 75 5d ad 83 f8 07 75 57 ad ad 83 f8 02 75 50 ad 85 c0 74 4b 97 6a 00 50 6a 08 56 53 50 6a 03 58 cd 80 83 c4 10 56 ad 91 ad 5e 0f c1 04 24 e2 41 91 0f b1 4c 24 04 75 12 6a 2c 56 53 50 b0 03 cd 80 83 c4 10 83 7e 24 00 75 13}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

