rule Trojan_Win64_Firedrill_YTD_2147922271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Firedrill.YTD!MTB"
        threat_id = "2147922271"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Firedrill"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "REG DELETE HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /V" ascii //weight: 1
        $x_1_2 = "FIREDRILL /f" ascii //weight: 1
        $x_1_3 = "Persistence Test Binary Blob" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

