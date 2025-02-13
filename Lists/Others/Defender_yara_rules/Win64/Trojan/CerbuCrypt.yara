rule Trojan_Win64_CerbuCrypt_SV_2147772867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CerbuCrypt.SV!MTB"
        threat_id = "2147772867"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CerbuCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_2 = "Windows Security" ascii //weight: 1
        $x_1_3 = "C:\\Windows\\System32\\svchost.exe" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "ResumeThread" ascii //weight: 1
        $x_1_6 = "QueueUserAPC" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

