rule Trojan_Win64_Ursu_SIB_2147806403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ursu.SIB!MTB"
        threat_id = "2147806403"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\zlib_config.ini" wide //weight: 1
        $x_1_2 = {48 89 c3 41 03 ca b8 ?? ?? ?? ?? f7 e1 41 ff c3 c1 ea ?? 89 d0 c1 e0 ?? 2b c2 f7 d8 03 c1 44 89 d1 0f b6 13 48 ff c3 33 d0 41 89 c2 41 88 11 49 ff c1 45 3b d8 72}  //weight: 1, accuracy: Low
        $x_1_3 = {44 0f be 09 45 85 c9 74 ?? 45 85 c0 74 ?? 41 83 f9 61 45 8d 51 ?? 45 0f 43 ca 41 89 c2 41 c1 e2 ?? 44 03 d0 43 8d 04 11 4c 8d 49 02 48 ff c1 85 d2 74 ?? 4c 89 c9 44 0f be 09 45 85 c9 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Ursu_EC_2147916819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ursu.EC!MTB"
        threat_id = "2147916819"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ursu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ptA8I5FY6QS6-mPg" ascii //weight: 1
        $x_1_2 = "8_9j/5SrIHRTVKaaxOt7oi0PZ/O1H5zK" ascii //weight: 1
        $x_1_3 = "VM6tMsRPsw" ascii //weight: 1
        $x_1_4 = "m4/u_YT0wH1Kwy8LoT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

