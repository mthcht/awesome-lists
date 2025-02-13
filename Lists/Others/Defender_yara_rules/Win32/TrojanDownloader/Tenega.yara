rule TrojanDownloader_Win32_Tenega_B_2147782390_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tenega.B!MTB"
        threat_id = "2147782390"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tenega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 0c 28 80 f1 80 88 0c 28 8b 4c 24 10 40 3b c1 72 ee}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 fc 8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 8a 1c 11 80 c3 fd 88 1c 11 8b 55 fc 80 04 11 03 90 8b 55 fc 8a 1c 11 80 f3 19 88 1c 11}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tenega_B_2147782390_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tenega.B!MTB"
        threat_id = "2147782390"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tenega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "xz.juzirl.com" ascii //weight: 1
        $x_1_2 = "download_quiet" ascii //weight: 1
        $x_1_3 = "ProxyEnable" ascii //weight: 1
        $x_1_4 = "creating socket" ascii //weight: 1
        $x_1_5 = "empty hostname" ascii //weight: 1
        $x_1_6 = {63 3a 5c 74 65 6d 70 5c 6e 73 [0-15] 2e 74 6d 70 5c [0-15] 2e 64 6c 6c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tenega_FGTR_2147794544_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tenega.FGTR!MTB"
        threat_id = "2147794544"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tenega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "0..,'(,&&,&&,&','(,&'*%&($%($%+%%+&&(&" ascii //weight: 1
        $x_1_2 = {30 40 00 5a 10 40 00 00 00 00 00 2a 00 5c 00 41 00 43 00 3a 00 5c 00 44}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDownloader_Win32_Tenega_BGHY_2147797364_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tenega.BGHY!MTB"
        threat_id = "2147797364"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tenega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 89 75 d2 66 89 7d da 66 89 55 84 66 89 4d 8e 66 89 7d 90 66 89 75 ba 66 89 4d bc 66 89 5d c2 66 89 45 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tenega_JITA_2147797885_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tenega.JITA!MTB"
        threat_id = "2147797885"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tenega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 14 85 e0 f9 07 01 33 14 85 e4 f9 07 01 33 14 85 e8 f9 07 01 33 14 85 ec f9 07 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tenega_A_2147899390_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tenega.A!MTB"
        threat_id = "2147899390"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tenega"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {72 75 6e 67 2e 6b 72 2f 44 4f 57 4e 2f [0-15] 2e 65 78 65}  //weight: 20, accuracy: Low
        $x_1_2 = "SecurityHealth" ascii //weight: 1
        $x_1_3 = "AVtype_info" ascii //weight: 1
        $x_1_4 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_5 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

