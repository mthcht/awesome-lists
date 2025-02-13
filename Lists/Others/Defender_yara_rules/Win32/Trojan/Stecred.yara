rule Trojan_Win32_Stecred_A_2147734622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stecred.A"
        threat_id = "2147734622"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stecred"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MicrosoftVirtualPC7UserServiceMakeSureWe'reTheOnlyOneMutex" wide //weight: 1
        $x_1_2 = "\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Enum\\PCI" wide //weight: 1
        $x_1_3 = "1-driver-vmsrvc" wide //weight: 1
        $x_1_4 = "vmmemctl" wide //weight: 1
        $x_1_5 = "prl_tg" wide //weight: 1
        $x_1_6 = "SELECT DISTINCT url FROM moz_places" wide //weight: 1
        $x_1_7 = "Google\\Chrome\\User Data\\Default\\History" wide //weight: 1
        $x_1_8 = "Mozilla\\Firefox\\Profiles\\*.*" wide //weight: 1
        $x_1_9 = "installed_software.browsers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

