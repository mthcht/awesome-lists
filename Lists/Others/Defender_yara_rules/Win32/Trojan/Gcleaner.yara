rule Trojan_Win32_Gcleaner_AGL_2147927502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gcleaner.AGL!MTB"
        threat_id = "2147927502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gcleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 6a 02 ff 75 ac ff d6 6a 04 8d 45 c8 c7 45 c8 ?? ?? ?? ?? 50 6a 41 ff 75 ac ff d6 83 7d c4 10 8d 45 b0 6a 01 0f 43 45 b0 53 6a 03 ff 77 40 ff 77 3c 6a 50 50 ff 75 ac}  //weight: 1, accuracy: Low
        $x_4_2 = "185.156.73.98" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Gcleaner_AGL_2147927502_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gcleaner.AGL!MTB"
        threat_id = "2147927502"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gcleaner"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {33 c0 30 98 64 0f 45 00 40 83 f8 0f 72}  //weight: 2, accuracy: High
        $x_1_2 = {80 35 30 0d 45 00 2e 80 35 31 0d 45 00 2e 80 35 32 0d 45 00 2e 80 35 33 0d 45 00 2e 80 35 34 0d 45 00 2e 80 35 35 0d 45 00 2e 80 35 36 0d 45 00 2e 80 35 37 0d 45 00 2e 80 35 38 0d 45 00 2e 34 2e a2 39 0d 45 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

