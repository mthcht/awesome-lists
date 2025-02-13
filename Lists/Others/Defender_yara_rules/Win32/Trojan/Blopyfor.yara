rule Trojan_Win32_Blopyfor_A_2147837052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Blopyfor.A!dha"
        threat_id = "2147837052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Blopyfor"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HOOK Beacon Sleep Start" ascii //weight: 1
        $x_1_2 = "HOOKCreateProcessInternalW" ascii //weight: 1
        $x_1_3 = "HOOK Beacon Sleep End" ascii //weight: 1
        $x_1_4 = "Enter Account Information for Task Registration" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

