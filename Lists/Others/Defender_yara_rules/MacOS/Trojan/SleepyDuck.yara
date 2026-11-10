rule Trojan_MacOS_SleepyDuck_DA_2147981816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MacOS/SleepyDuck.DA!MTB"
        threat_id = "2147981816"
        type = "Trojan"
        platform = "MacOS: "
        family = "SleepyDuck"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6f 30 78 5d 3a 73 68 2d 73 0d 0a 25 64 70 73 2d 70 2d 6f 72 72 2d 6e 3e 0a 20 5b 28 22 22 29 29 20 20 20 5e 20 29 0a 20 2b 3a 0a 20 40 73 20 2d 3e 20 50 42 20 6e 3d 5d 5b 7d 0a 5d 0a 5c 6e 5c 72 5c 74 5c 75 5c 55 5b 20 20 5d 0a 20 09 20 32 35 7b 7d 22 3a 29 28 3b 20 3a 25 38 30 20 2c 68 32 25 76 20 09 4f 4b 69 76 69 70 3f 3f 35 33 5d 29 22 0a 6f 73 69 64 4c 6c 4c 74 4c 75 4d 6e 43 63 5c 5c 5c 22 54 6f 41 34 56 31 56 36 56 32 56 33 56 35 41 33}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

