rule Ransom_Win64_Ransomhub_B_2147910975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Ransomhub.B"
        threat_id = "2147910975"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Ransomhub"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KillServices bool \"json:\\\"kill_services\\\"\"; SetWallpaper bool \"json:\\\"set_wallpaper\\\"\";" ascii //weight: 1
        $x_1_2 = "SelfDelete bool \"json:\\\"self_delete\\\"\"; RunningOne bool \"json:\\\"running_one\\\"\"" ascii //weight: 1
        $x_1_3 = "LocalDisks bool \"json:\\\"local_disks\\\"\"; NetworkShares bool \"json:\\\"network_shares\\\"\";" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win64_Ransomhub_C_2147911916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Ransomhub.C!ldr"
        threat_id = "2147911916"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Ransomhub"
        severity = "Critical"
        info = "ldr: loader component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 69 00 6e 00 69 00 00 ?? 00 00 42 00 49 00 4e 00 00 00 2d 70 61 73 73 00 00 00 70 61 73 73 3a 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

