rule Backdoor_Win64_Silver_PABH_2147894560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Silver.PABH!MTB"
        threat_id = "2147894560"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Silver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 33 c9 4c 8b c1 49 83 ca ff 49 8b c2 48 ff c0 44 38 0c 01 75 f7 48 85 c0 74 1e 80 31 e6 41 ff c1 48 ff c1 49 8b d2 48 ff c2 41 80 3c 10 00 75 f6 49 63 c1 48 3b c2 72 e2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

