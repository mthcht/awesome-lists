rule Trojan_Win32_Yangxiay_A_2147617141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yangxiay.A"
        threat_id = "2147617141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yangxiay"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 52 65 63 79 63 6c 65 72 5c [0-16] 5f 43 6f 6e 66 69 67 2e 49 6e 69}  //weight: 1, accuracy: Low
        $x_1_2 = "\\Program Files\\Internet Explorer\\iexplore.exe.tmp" ascii //weight: 1
        $x_1_3 = "SYSTEM\\CurrentControlSet\\Services\\gRtEOgFRz" ascii //weight: 1
        $x_1_4 = "SYSTEM\\CurrentControlSet\\Services\\Autghorhization" ascii //weight: 1
        $x_10_5 = {3c 69 66 72 61 6d 65 20 73 72 63 3d 22 00 22 00 20 77 69 64 74 68 3d 22 30 22 00 20 68 65 69 67 68 74 3d 22 30 22 00 20 66 72 61 6d 65 62 6f 72 64 65 72 3d 22 00 30 22 3e 3c 2f 69 66 72 61 6d 65 3e}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Yangxiay_A_2147617142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Yangxiay.A!sys"
        threat_id = "2147617142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Yangxiay"
        severity = "Critical"
        info = "sys: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bb 10 00 00 c0 8b 75 0c 8b 46 60 8b 48 0c 8b 50 10 89 55 e4 8b 7e 3c 8b 40 04 89 45 d4 81 f9 4b e1 22 00 0f 85 ?? 00 00 00 83 65 fc 00 6a 04 5b 53 53 52 ff ?? ?? ?? 01 00}  //weight: 1, accuracy: Low
        $x_1_2 = "DisPatchCreate!" ascii //weight: 1
        $x_1_3 = "KeServiceDescriptorTable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

