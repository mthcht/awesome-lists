rule Trojan_Win32_Wenga_A_2147654222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wenga.A"
        threat_id = "2147654222"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wenga"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hrundll32.exe" ascii //weight: 1
        $x_1_2 = "bSOFTWARE\\Microsoft\\Windows\\currentversion\\run" ascii //weight: 1
        $x_1_3 = "ameganewnewdriver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

