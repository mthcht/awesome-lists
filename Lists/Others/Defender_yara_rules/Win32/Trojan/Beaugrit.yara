rule Trojan_Win32_Beaugrit_EB_2147748462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Beaugrit.EB!MTB"
        threat_id = "2147748462"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Beaugrit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ":\\Program Files\\MuAS_Virus.exe" wide //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

