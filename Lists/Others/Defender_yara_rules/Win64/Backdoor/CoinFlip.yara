rule Backdoor_Win64_CoinFlip_A_2147946916_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/CoinFlip.A!dha"
        threat_id = "2147946916"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "CoinFlip"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src\\changebackup.rs" ascii //weight: 1
        $x_1_2 = "src\\screenshot.rs" ascii //weight: 1
        $x_1_3 = "src\\tasklist.rs" ascii //weight: 1
        $x_1_4 = "src\\upload_file.rs" ascii //weight: 1
        $x_1_5 = "src\\dnshostname.rs" ascii //weight: 1
        $x_1_6 = "src\\downloadfile.rs" ascii //weight: 1
        $x_1_7 = "src\\ipconfig.rs" ascii //weight: 1
        $x_1_8 = "src\\killprogram.rs" ascii //weight: 1
        $x_1_9 = "src\\runcommand.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

