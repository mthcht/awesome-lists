rule Trojan_Win32_EliteBar_2147570322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/EliteBar"
        threat_id = "2147570322"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "EliteBar"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 6c 69 74 65 42 61 72 49 6d 70 6c 64 00}  //weight: 1, accuracy: High
        $x_1_2 = "DllCanUnloadNow" ascii //weight: 1
        $x_1_3 = "InternetCheckConnectionA" ascii //weight: 1
        $x_1_4 = "EliteToolBar Dynamic Link Library" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

