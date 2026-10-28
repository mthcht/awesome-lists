rule Trojan_Win64_VallyRat_SN_2147977398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VallyRat.SN!MTB"
        threat_id = "2147977398"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VallyRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Microsoft Windows Defender Antivirus" ascii //weight: 1
        $x_1_2 = "Trend Micro (PC-cillin) Antivirus" ascii //weight: 1
        $x_1_3 = "Antivirus Detector" ascii //weight: 1
        $x_1_4 = "atlTraceSecurity" ascii //weight: 1
        $x_1_5 = "UG9ydDE6MzIxNTE=" ascii //weight: 1
        $x_1_6 = "UG9ydDI6MzIxNTI=" ascii //weight: 1
        $x_1_7 = "UG9ydDM6MjEzNTg=" ascii //weight: 1
        $x_2_8 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_9 = "SeLoadDriverPrivilege" ascii //weight: 1
        $x_1_10 = "[ERROR] DuplicateTokenEx LinkedToken:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

