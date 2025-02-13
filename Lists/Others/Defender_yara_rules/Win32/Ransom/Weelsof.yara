rule Ransom_Win32_Weelsof_A_2147655996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Weelsof.A"
        threat_id = "2147655996"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Weelsof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii //weight: 1
        $x_1_3 = "external_ip_file_name" ascii //weight: 1
        $x_1_4 = "explorer_new.exe" ascii //weight: 1
        $x_1_5 = {64 69 6c 6c 79 2f [0-16] 2e 70 68 70}  //weight: 1, accuracy: Low
        $x_1_6 = {b8 01 00 00 00 2b c1 89 44 24 1c b8 02 00 00 00 8b d1 2b c2 89 44 24 18 b8 03 00 00 00 83 c4 08 33 f6 2b c1 89 44 24 08 33 d2 8b c6 f7 f7 8b 44 24 14 8d 8c 34 e8 00 00 00 03 c1 83 c6 04 0f b6 14 1a 00 11 33 d2 f7 f7 8b 44 24 10 03 c1 0f b6 14 1a 00 51 01 33 d2}  //weight: 1, accuracy: High
        $x_2_7 = {8a 16 8a ca 80 e2 0f c0 e9 04 80 f9 09 53 0f 9e c3 fe cb 80 e3 07 80 c3 30 02 d9 80 fa 09 0f 9e c1 fe c9 80 e1 07 80 c1 30 02 ca 88 18 88 48 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Weelsof_C_2147658320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Weelsof.C"
        threat_id = "2147658320"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Weelsof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "locker_filename" ascii //weight: 1
        $x_1_2 = "cfg_file_lock_name_seed" ascii //weight: 1
        $x_1_3 = "can't unpack design archive" ascii //weight: 1
        $x_1_4 = "79.76.71.166" ascii //weight: 1
        $x_1_5 = "$_NOTICE_BLOCK_%d_" ascii //weight: 1
        $x_1_6 = "$_ERR_MSG_%d_" ascii //weight: 1
        $x_1_7 = "$_OK_MSG_%d_" ascii //weight: 1
        $x_1_8 = "$_IP_ADDR_$" ascii //weight: 1
        $x_4_9 = {fe c2 0f b6 f2 88 90 00 01 00 00 0f b6 14 06 00 90 01 01 00 00 0f b6 90 01 01 00 00 (0f b6 14 02 8a|8a 1c 06 0f b6) 88 14 06 0f b6 90 01 01 00 00 88 1c 02 8a 90 00 01 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_4_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Weelsof_E_2147659379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Weelsof.E"
        threat_id = "2147659379"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Weelsof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<!-- $_NOTICE_BLOCK_%d_START_$ -->" ascii //weight: 1
        $x_1_2 = "/get_dsn.php" ascii //weight: 1
        $x_1_3 = "$_IP_ADDR_$" ascii //weight: 1
        $x_1_4 = {6a 00 68 00 f7 0c 84 6a 00 6a 00 6a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

