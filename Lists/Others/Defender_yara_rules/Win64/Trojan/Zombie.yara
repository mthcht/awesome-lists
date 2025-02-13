rule Trojan_Win64_Zombie_DS_2147888637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zombie.DS!MTB"
        threat_id = "2147888637"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zombie"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2f 63 20 64 65 6c 20 00 43 4f 4d 53 50 45 43 00 72 62 00 00 5f 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "Zombie.exe" ascii //weight: 1
        $x_1_3 = "cfdisk.exe" ascii //weight: 1
        $x_1_4 = {cf eb d5 d2 bb d8 ce c4 bc fe 2d 5f 2d 00 00 20 20 c1 aa cf b5 d7 f7 d5 df 20 bb d6 b8 b4 cb f9 d3 d0 ce c4 bc fe}  //weight: 1, accuracy: High
        $x_1_5 = {90 41 57 41 56 41 55 41 54 55 57 56 53 48 83 ec 38 31 d2 48 89 cf e8 f6 fd ff ff 48 89 c5 f6 47 50 01 0f 84 c9 00 00 00 48 8b 77 28 48 85 f6 0f 84 dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

