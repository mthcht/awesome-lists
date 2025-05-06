rule Worm_Win32_Sfone_A_2147609829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sfone.A"
        threat_id = "2147609829"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfone"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {85 c0 75 1f 8b 85 ?? ?? ff ff 50 6a 00 68 ff 0f 1f 00 ff 15 58 67 41 00 89 c6 6a 00 56 ff 15 ?? ?? 41 00 83 c3 01 8b 04 9d ?? ?? 41 00 85 c0 75 a8 8d 85 ?? ?? ff ff 50 57 e8 8a 0c 00 00 83 f8 01 0f 84 00 ff ff ff}  //weight: 4, accuracy: Low
        $x_1_2 = "mutex666" ascii //weight: 1
        $x_1_3 = "thisisapassword!" ascii //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_5 = "AVprotect9X" ascii //weight: 1
        $x_1_6 = "notes.txt.exe" ascii //weight: 1
        $x_1_7 = "readme.txt.exe" ascii //weight: 1
        $x_1_8 = "incoming" ascii //weight: 1
        $x_1_9 = "share" ascii //weight: 1
        $x_1_10 = "upskirt" ascii //weight: 1
        $x_1_11 = "annie" ascii //weight: 1
        $x_1_12 = "nipples" ascii //weight: 1
        $x_1_13 = "glans" ascii //weight: 1
        $x_1_14 = "vagina" ascii //weight: 1
        $x_1_15 = "IcmpSendEcho" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((11 of ($x_1_*))) or
            ((1 of ($x_4_*) and 7 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Sfone_ECP_2147940178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sfone.ECP!MTB"
        threat_id = "2147940178"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 e0 1f 50 59 8d 04 8d ?? ?? ?? ?? 8b 10 89 15 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 89 10 a1}  //weight: 5, accuracy: Low
        $x_5_2 = {99 f7 f9 89 14 bb 83 c7 01 89 f8 39 f0}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Sfone_BY_2147940707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sfone.BY!MTB"
        threat_id = "2147940707"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sfone"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 d8 0f be c0 83 c0 41 88 45 fd 8d 45 fd 50 ff 15 ?? ?? ?? 00 89 44 9d 94 83 c3 01 83 fb 1a 7c}  //weight: 2, accuracy: Low
        $x_1_2 = "8tx4r7lq8l7optghd7es0avjiciv2x1nvbwffl5bryvm1" ascii //weight: 1
        $x_1_3 = "96txft9f" ascii //weight: 1
        $x_1_4 = "m4jud9vcs5sj8ir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

