rule Trojan_Win32_Floxif_C_2147661097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Floxif.C"
        threat_id = "2147661097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Floxif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8a 46 03 3c 01 8d 46 04 74 ?? 8a 08 f6 d1 84 c9 88 08}  //weight: 1, accuracy: Low
        $x_1_2 = {c6 45 a0 e9 03 fa 8b c7 8b 08 89 4d c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Floxif_AV_2147799364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Floxif.AV!MTB"
        threat_id = "2147799364"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Floxif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FbRobot" ascii //weight: 3
        $x_3_2 = "/s/seemorebty/index2.php" ascii //weight: 3
        $x_3_3 = "MIGJAoGBAM84QY/eHMjGXDDAlYv" ascii //weight: 3
        $x_3_4 = "WeoiJu08hW7a5SQlPGFCPvBaTIeGCbEWdMBprxeqMiisxegf1sL3AgMBAAE=" ascii //weight: 3
        $x_3_5 = "Software\\ffdroider" ascii //weight: 3
        $x_3_6 = "encrypted_key" ascii //weight: 3
        $x_3_7 = "os_crypt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Floxif_AW_2147799365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Floxif.AW!MTB"
        threat_id = "2147799365"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Floxif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "FbRobot" ascii //weight: 3
        $x_3_2 = "PK11SDR_Decrypt" ascii //weight: 3
        $x_3_3 = "/profile.php?id=" ascii //weight: 3
        $x_3_4 = "z9Yzbx5JbVSUWmTh" ascii //weight: 3
        $x_3_5 = "encryptedPassword" ascii //weight: 3
        $x_3_6 = "encrypted_key" ascii //weight: 3
        $x_3_7 = "os_crypt" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Floxif_YBZ_2147914760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Floxif.YBZ!MTB"
        threat_id = "2147914760"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Floxif"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b cf f7 e7 c1 ea 04 6b c2 16 2b c8 2b ce 8a 44 0c 24 32 87 28 49 10 10 88 04 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

