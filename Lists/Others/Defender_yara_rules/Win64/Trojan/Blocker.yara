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

rule Trojan_Win64_Blocker_NB_2147960206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blocker.NB!MTB"
        threat_id = "2147960206"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 8b 44 24 28 83 a0 a8 03 00 00 fd 45 33 c9 4c 8d 44 24 20 48 8d 54 24 48 48 8d 4d 80 e8 eb fd ff ff 8b 44 24 68 48 8b 8d 90 01 00 00 48 33 cc e8 1c 80 00 00 4c 8d 9c 24 a0 02 00 00 49 8b 5b 18 49 8b 7b 20 49 8b e3}  //weight: 2, accuracy: High
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "winlogsvc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

