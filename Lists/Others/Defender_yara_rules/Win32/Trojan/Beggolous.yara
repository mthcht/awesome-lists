rule Trojan_Win32_Beggolous_A_2147727728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Beggolous.A"
        threat_id = "2147727728"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Beggolous"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AllocateAndInitializeSid" ascii //weight: 1
        $x_1_2 = "SHGetFolderPathW" ascii //weight: 1
        $x_1_3 = "RegSetValueExW" ascii //weight: 1
        $x_10_4 = "D:\\Projects\\src\\bypassuac\\branches\\RegTool\\build\\Release\\regtool.pdb" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

