rule Trojan_Win64_Blocker_DAO_2147851988_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blocker.DAO!MTB"
        threat_id = "2147851988"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 0f b6 84 24 14 05 00 00 ff c2 48 ff c1 30 41 ff 8b 5c 24 30 3b d3 72}  //weight: 2, accuracy: High
        $x_2_2 = {48 89 5c 24 30 48 8d 0d [0-4] 45 8d 41 01 ba 00 00 00 c0 89 5c 24 28 48 89 6c 24 68 c7 44 24 20 02 00 00 00 ff 15}  //weight: 2, accuracy: Low
        $x_1_3 = "brbconfig.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

