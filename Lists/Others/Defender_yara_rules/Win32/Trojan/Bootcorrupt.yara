rule Trojan_Win32_Bootcorrupt_E_2147727459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bootcorrupt.E!dha"
        threat_id = "2147727459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bootcorrupt"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MBR Killer" ascii //weight: 1
        $x_1_2 = "advapi32::OpenProcessToken(i, i, *i) i (-1, 0x0008|0x0020, .r1) i .r0" ascii //weight: 1
        $x_1_3 = "kernel32::VirtualProtect(p, i, i, *i) i (r1, 6, 0x40, .r2) .r0" ascii //weight: 1
        $x_1_4 = "\\\\.\\PHYSICALDRIVE%d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

