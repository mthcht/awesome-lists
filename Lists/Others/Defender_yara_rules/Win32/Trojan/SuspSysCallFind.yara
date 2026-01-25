rule Trojan_Win32_SuspSysCallFind_A_2147961701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SuspSysCallFind.A"
        threat_id = "2147961701"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspSysCallFind"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {f6 04 25 08 03 fe 7f 01}  //weight: 1, accuracy: High
        $x_1_2 = {75 03 0f 05 c3 cd 2e c3 ?? ?? 4c 8b d1 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

