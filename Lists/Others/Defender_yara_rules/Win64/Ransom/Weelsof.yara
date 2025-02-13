rule Ransom_Win64_Weelsof_A_2147667201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Weelsof.A"
        threat_id = "2147667201"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Weelsof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 6e 66 69 67 5f 66 69 6c 65 5f [0-5] 6e 61 6d 65 5f 73 65 65 64}  //weight: 1, accuracy: Low
        $x_1_2 = "locker_file_name" ascii //weight: 1
        $x_1_3 = "core_remote_entry" ascii //weight: 1
        $x_1_4 = "/get_dsn.php" ascii //weight: 1
        $x_1_5 = "/get_coce.php" ascii //weight: 1
        $x_1_6 = {2f 74 6f 70 69 63 2e 70 68 70 00 [0-4] 00 41 43 43 45 50 54 45 44 00}  //weight: 1, accuracy: Low
        $x_6_7 = {48 8b d9 c7 40 ?? 75 00 73 00 c7 40 ?? 65 00 72 00 c7 40 ?? 33 00 32 00 c7 40 ?? 2e 00 64 00 c7 40 ?? 6c 00 6c 00 48 83 79}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

