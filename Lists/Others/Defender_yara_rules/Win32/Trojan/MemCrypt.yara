rule Trojan_Win32_MemCrypt_MK_2147787718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MemCrypt.MK!MTB"
        threat_id = "2147787718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MemCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MEMZ Trojan" ascii //weight: 1
        $x_1_2 = "Don't kill my trojan" ascii //weight: 1
        $x_1_3 = "your computer fucked by me" ascii //weight: 1
        $x_1_4 = "You can't reboot" ascii //weight: 1
        $x_1_5 = "Your computer won't boot up again" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

