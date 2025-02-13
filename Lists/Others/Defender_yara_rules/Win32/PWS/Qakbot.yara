rule PWS_Win32_Qakbot_MFP_2147786661_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Qakbot.MFP!MTB"
        threat_id = "2147786661"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c7 45 c4 92 20 00 00 c7 45 c0 80 19 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 e0 90 b9 03 00 c7 45 dc ad 08 00 00 c7 45 d8 7b 00 00 00 c7 45 d4 02 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {89 45 ec c7 45 b0 8a a5 08 00 8b 45 ec 3b 45 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Qakbot_MFP_2147786661_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Qakbot.MFP!MTB"
        threat_id = "2147786661"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Qakbot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f b6 06 46 85 c0 74 ?? 57 29 3c e4 09 0c e4 52 c7 04 e4 ?? ?? ?? ?? 59 bb ?? ?? ?? ?? 56 8f 45 f4 ff 75 f4 5a c7 45 fc ?? ?? ?? ?? d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 ?? 57 33 3c e4 09 df 83 e0 00 09 f8 5f 81 e1 00 00 00 00 33 0c e4 83 ec ?? aa 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

