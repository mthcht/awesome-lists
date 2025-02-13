rule Trojan_Win32_Hadoc_A_2147694171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hadoc.A!dha"
        threat_id = "2147694171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hadoc"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%RMTPath%\\RMT_SecureBrowsing.exe" ascii //weight: 1
        $x_1_2 = "%CurrentDrive%:\\RMT_UserData\\%A_LoopFileName%" ascii //weight: 1
        $x_1_3 = "Keybd hook: %s" ascii //weight: 1
        $x_1_4 = "Mouse hook: %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

