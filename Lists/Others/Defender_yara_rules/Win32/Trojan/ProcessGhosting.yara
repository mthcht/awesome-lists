rule Trojan_Win32_ProcessGhosting_A_2147936644_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ProcessGhosting.A!MTB"
        threat_id = "2147936644"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcessGhosting"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "process-ghosting" ascii //weight: 1
        $x_1_2 = "AdjustTokenPrivileges" ascii //weight: 1
        $x_1_3 = {48 83 ec 30 48 8b d9 4c 8b f2 48 8b 53 18 4c 8d 7b 18 48 8b 49 10 48 8b c2 48 2b c1 45 33 ed 48 83 f8 09}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

