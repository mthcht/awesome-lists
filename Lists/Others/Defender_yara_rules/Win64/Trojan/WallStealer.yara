rule Trojan_Win64_WallStealer_PGWS_2147964752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/WallStealer.PGWS!MTB"
        threat_id = "2147964752"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "WallStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2b cb 0f 57 c8 f3 41 0f 6f 04 3b f3 41 0f 7f 0c 30 45 8d 43 10 f3 0f 6f 4c 0c 60 43 8d 0c 1f 0f 57 c8 f3 41 0f 6f 04 38 f3 41 0f 7f 0c 33 41 83 c3 40 f3 0f 6f 4c 0c 60 0f 57 c8 f3 41 0f 7f 0c 30 3b c5 72}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

