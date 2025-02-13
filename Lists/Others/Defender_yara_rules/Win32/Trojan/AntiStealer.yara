rule Trojan_Win32_AntiStealer_A_2147893388_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AntiStealer.A!MTB"
        threat_id = "2147893388"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AntiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "AntiStealer" wide //weight: 2
        $x_2_2 = "GET %s HTTP/1.1" ascii //weight: 2
        $x_2_3 = "Host: %s" ascii //weight: 2
        $x_2_4 = "User-Agent: %s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

