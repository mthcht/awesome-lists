rule Trojan_Win64_Razy_RB_2147844061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Razy.RB!MTB"
        threat_id = "2147844061"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 63 44 24 40 48 3d 00 06 03 00 73 26 48 63 44 24 40 48 8d 0d ?? ?? 00 00 0f b6 04 01 35 ad 00 00 00 48 63 4c 24 40 48 8d 15 ?? ?? 00 00 88 04 0a eb c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Razy_NR_2147849145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Razy.NR!MTB"
        threat_id = "2147849145"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {48 81 ee 04 00 00 00 41 81 f2 ?? ?? ?? ?? 66 41 81 c2 ?? ?? 44 8b 16 45 33 d3 e9 ?? ?? ?? ?? 4c 8b 0f 66 d3 f2 48 81 c7 ?? ?? ?? ?? 40 c0 ed 1e}  //weight: 5, accuracy: Low
        $x_1_2 = "JNZNIzGYB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Razy_AVE_2147943969_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Razy.AVE!MTB"
        threat_id = "2147943969"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 0f b7 01 41 8b 08 8b 14 86 49 03 cb 33 c0 8a 19 49 03 d3 84 db 74 24 c1 c0 03 48 ff c1 89 44 24 10 30 5c 24 10 8a 19 84 db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Razy_LMA_2147961626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Razy.LMA!MTB"
        threat_id = "2147961626"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "153"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[DEBUG] Current:" ascii //weight: 1
        $x_2_2 = "[DEBUG] Download URL:" ascii //weight: 2
        $x_3_3 = "[DEBUG] Downloading to:" ascii //weight: 3
        $x_4_4 = "downloadUrl" ascii //weight: 4
        $x_5_5 = "[ERROR] File too small, probably not valid" ascii //weight: 5
        $x_6_6 = "[ERROR] Failed to create new file" ascii //weight: 6
        $x_7_7 = "[SUCCESS] Downloaded" ascii //weight: 7
        $x_8_8 = "[DEBUG] Deleting old backup..." ascii //weight: 8
        $x_9_9 = "[DEBUG] Renaming current to .old..." ascii //weight: 9
        $x_10_10 = "[ERROR] Failed to rename current file" ascii //weight: 10
        $x_11_11 = "[DEBUG] Moving new file to current..." ascii //weight: 11
        $x_12_12 = "[ERROR] Failed to move new file" ascii //weight: 12
        $x_13_13 = "[DEBUG] Launching new process..." ascii //weight: 13
        $x_14_14 = "c timeout 3 >nul" ascii //weight: 14
        $x_15_15 = "AUTHENTICATION_SUCCESSFUL" ascii //weight: 15
        $x_16_16 = "[SUCCESS] New process started" ascii //weight: 16
        $x_17_17 = "[ERROR] Failed to launch new process" ascii //weight: 17
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

