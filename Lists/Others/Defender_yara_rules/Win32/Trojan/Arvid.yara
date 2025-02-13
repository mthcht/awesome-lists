rule Trojan_Win32_Arvid_A_2147691804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Arvid.A!dha"
        threat_id = "2147691804"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Arvid"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "designers/img/sunny30.html" ascii //weight: 1
        $x_1_2 = "events/get_temp.php" ascii //weight: 1
        $x_1_3 = "mixedwork.com" ascii //weight: 1
        $x_1_4 = "events/add_temp.php" ascii //weight: 1
        $x_5_5 = "ldsfdsfdsfZXXwelcome" ascii //weight: 5
        $x_1_6 = "stdio/pic/1.html" ascii //weight: 1
        $x_1_7 = "do/get_temp.php" ascii //weight: 1
        $x_2_8 = "pstcmedia.com" ascii //weight: 2
        $x_1_9 = "do/add_temp.php" ascii //weight: 1
        $x_1_10 = "REMOTE_USER:" ascii //weight: 1
        $x_2_11 = "User-Agent: Skype" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((8 of ($x_1_*))) or
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Arvid_C_2147692585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Arvid.C!dha"
        threat_id = "2147692585"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Arvid"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "advtravel.info" wide //weight: 5
        $x_5_2 = "linksis.info/sys/pat/" wide //weight: 5
        $x_2_3 = "/tools/wininstl.exe" wide //weight: 2
        $x_2_4 = "/tools/dotnet2.exe" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_2_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Arvid_E_2147692589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Arvid.E!dha"
        threat_id = "2147692589"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Arvid"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "new/chang_fflag.php" ascii //weight: 1
        $x_1_2 = "new/all_file_info.php" ascii //weight: 1
        $x_1_3 = "new/chang_flag.php" ascii //weight: 1
        $x_1_4 = "new/chang_rflag.php" ascii //weight: 1
        $x_1_5 = "new/view_file_order.php" ascii //weight: 1
        $x_1_6 = "new/view_random_order.php" ascii //weight: 1
        $x_1_7 = "new/view_flash_files.php" ascii //weight: 1
        $x_1_8 = "new/add_user.php" ascii //weight: 1
        $x_4_9 = "mediahitech.info" ascii //weight: 4
        $x_4_10 = "SELECT * FROM Win32_DiskDrive" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

