rule Backdoor_Win64_StuffieBear_A_2147978180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/StuffieBear.A!sms"
        threat_id = "2147978180"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "StuffieBear"
        severity = "Critical"
        info = "sms: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {56 8b f0 0f b6 44 24 08 57 99 bf 6b 04 00 00 f7 ff 80 ea 58 85 f6 76 19 80 7c 24 10 00 8a 01 74 06 2a c2 32 c2 eb 04 32 c2 02 c2 88 01 41 4e}  //weight: 10, accuracy: High
        $x_10_2 = {8b f1 8b 4e 04 8b 16 57 8b f8 8b c1 c1 f8 05 8b da c1 e3 0c 33 c3 35 2c 93 a5 95 39 46 08 74 36 57 6a 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

