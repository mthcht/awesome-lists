rule Trojan_Win32_CredHooker_A_2147769548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredHooker.A!MTB"
        threat_id = "2147769548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredHooker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Windows\\Temp\\106.607" ascii //weight: 1
        $x_1_2 = "addr_wsaconnect %p" ascii //weight: 1
        $x_1_3 = "stoping dll" ascii //weight: 1
        $x_1_4 = "127.0.0.1" ascii //weight: 1
        $x_1_5 = "loading dll" ascii //weight: 1
        $x_1_6 = "ws2_32.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

