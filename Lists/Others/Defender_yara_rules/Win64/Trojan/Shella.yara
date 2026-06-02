rule Trojan_Win64_Shella_MK_2147970724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Shella.MK!MTB"
        threat_id = "2147970724"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Shella"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {c6 45 20 55 c6 45 21 75 c6 45 22 69 c6 45 23 64 c6 45 24 46 c6 45 25 72 c6 45 26 6f c6 45 27 6d c6 45 28 53 c6 45 29 74 c6 45 2a 72 c6 45 2b 69 c6 45 2c 6e c6 45 2d 67 c6 45 2e 41 c6 45 2f}  //weight: 10, accuracy: High
        $x_5_2 = {c6 45 30 56 c6 45 31 69 c6 45 32 72 c6 45 33 74 c6 45 34 75 c6 45 35 61 c6 45 36 6c c6 45 37 50 c6 45 38 72 c6 45 39 6f c6 45 3a 74 c6 45 3b 65 c6 45 3c 63 c6 45 3d 74 c6 45 3e 00 c6 45 3f}  //weight: 5, accuracy: High
        $x_3_3 = "injection_initialize" ascii //weight: 3
        $x_2_4 = "execInThread" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

