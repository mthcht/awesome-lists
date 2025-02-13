rule Trojan_Win32_BlackCat_SAA_2147899920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BlackCat.SAA!MTB"
        threat_id = "2147899920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BlackCat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Trying to remove shadow copies" ascii //weight: 2
        $x_2_2 = "impersno-vm-killno-vm-snapshot-killno-vm-kill-names" ascii //weight: 2
        $x_1_3 = "Invalid config!" ascii //weight: 1
        $x_1_4 = "Invalid public key" ascii //weight: 1
        $x_1_5 = "Invalid access token" ascii //weight: 1
        $x_1_6 = "panic payload panicked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

