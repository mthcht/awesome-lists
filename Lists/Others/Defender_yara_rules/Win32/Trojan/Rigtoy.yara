rule Trojan_Win32_Rigtoy_17744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rigtoy"
        threat_id = "17744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rigtoy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "%s?gid=%d&%s" ascii //weight: 3
        $x_3_2 = "AdobeAid.dll" ascii //weight: 3
        $x_1_3 = "baidu.com" ascii //weight: 1
        $x_2_4 = "GPlayer.dll" ascii //weight: 2
        $x_3_5 = "Sys_Run_3" ascii //weight: 3
        $x_1_6 = "yahoo.com.cn" ascii //weight: 1
        $x_1_7 = "zhongsou.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rigtoy_17744_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rigtoy"
        threat_id = "17744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rigtoy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {52 75 6e 00 00 00 00 20 00 00 00 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 00 00 2e 63 75 72 00 00 00 00 5c 63 75 72 73 6f 72 00 2e 73 79 73 00 00 00 00 5c 64 72 69 76 65 72 73 00 00 00 00 2e 74 74 66 00 00 00 00 2e 65 78 65 00 00 00 00 2e 64 6c 6c 00 00 00 00 5c 4d 53 00 20 2d 73 00 20 2d 69}  //weight: 2, accuracy: High
        $x_2_2 = "Sys_Run_3" ascii //weight: 2
        $x_2_3 = "SGMIGEX" ascii //weight: 2
        $x_2_4 = "AdobeAid.dll" ascii //weight: 2
        $x_2_5 = "MsNetEx.exe" ascii //weight: 2
        $x_2_6 = "Module_Raw" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_Win32_Rigtoy_17744_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rigtoy"
        threat_id = "17744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rigtoy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 00 00 00 2e 63 75 72 00 00 00 00 5c 63 75 72 73 6f 72 00 2e 73 79 73 00 00 00 00 5c 64 72 69 76 65 72 73 00 00 00 00 2e 74 74 66 00 00 00 00 2e 65 78 65 00 00 00 00 2e 64 6c 6c 00 00 00 00 5c 4d 53}  //weight: 2, accuracy: High
        $x_2_2 = {4f 4c 45 4e 00 00 00 00 45 54 2e 64 6c 6c 00 00 41 64 6f 62 65 00 00 00 41 69 64 2e 64 6c 6c 00 4d 73 4e 65 74 00 00 00 45 78 2e 65 78 65 00 00 49 4d 53 47 4d 49 47}  //weight: 2, accuracy: High
        $x_2_3 = {53 79 73 5f 00 00 00 00 52 75 6e 5f 32 00 00 00 52 75 6e 5f 31 00 00 00 6d 61 70 00 52 75 6e 5f 33}  //weight: 2, accuracy: High
        $x_2_4 = "SGMIGEX" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

