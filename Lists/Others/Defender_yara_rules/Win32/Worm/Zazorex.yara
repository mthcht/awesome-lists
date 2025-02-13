rule Worm_Win32_Zazorex_C_2147653314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Zazorex.C"
        threat_id = "2147653314"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Zazorex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT value  FROM moz_cookies WHERE name = '%s' ORDER BY name;" ascii //weight: 1
        $x_1_2 = "&to_offline=false&to_idle=false&post_form_id=%s&fb_dtsg=%s&lsd&post_form_id_source=AsyncRequest" ascii //weight: 1
        $x_1_3 = "/ajax/chat/buddy_list.php?__a=1" ascii //weight: 1
        $x_1_4 = "/ajax/chat/send.php?__a=1" ascii //weight: 1
        $x_1_5 = "captcha" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Zazorex_D_2147654364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Zazorex.D"
        threat_id = "2147654364"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Zazorex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/ajax/chat/send.php?__a=1" ascii //weight: 1
        $x_1_2 = {50 ff 75 f8 ff 55 f0 8b 45 fc ff 70 04 8b 45 0c 68 ?? ?? ?? ?? ff 30 e8 ?? ?? ?? ?? 83 c4 24 ff 75 fc ff 55 f4 59 ff 75 f8 ff d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Zazorex_E_2147661191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Zazorex.E"
        threat_id = "2147661191"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Zazorex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2f 63 20 70 69 6e 67 20 31 2e 31 2e 31 2e 31 20 2d 6e 20 31 20 2d 77 20 33 30 30 30 20 3e 3e 20 4e 55 4c 20 26 20 64 65 6c 20 00}  //weight: 1, accuracy: High
        $x_1_2 = {2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 63 5f 75 73 65 72 00 2e 66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 78 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 6d 65 2f 66 72 69 65 6e 64 73 3f 66 69 65 6c 64 73 3d 69 64 26 61 63 63 65 73 73 5f 74 6f 6b 65 6e 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {08 66 61 63 c7 45 ?? 65 62 6f 6f 66 c7 45 ?? 6b 00 c7 45 ?? 06 63 5f 75 c7 45 ?? 73 65 72 00 c7 (45 ??|85 ?? ?? ?? ??) 02 78 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

