rule Trojan_Win32_Raccoonstealer_RW_2147780241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Raccoonstealer.RW!MTB"
        threat_id = "2147780241"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Raccoonstealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\system32\\CODAF6" ascii //weight: 1
        $x_1_2 = "C:\\Windows\\system32\\CODEJO" ascii //weight: 1
        $x_1_3 = "C:\\Windows\\system32\\CODD25" ascii //weight: 1
        $x_1_4 = "rermfcsedawad777emuix" ascii //weight: 1
        $x_1_5 = "CryptAcquireContextW" ascii //weight: 1
        $x_1_6 = "GetTickCount" ascii //weight: 1
        $x_1_7 = "RegOpenKeyExW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

