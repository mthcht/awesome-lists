rule Trojan_Win32_Drumveet_B_2147811723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Drumveet.B!dha"
        threat_id = "2147811723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Drumveet"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /F /IM \\cookies.sqlite" ascii //weight: 1
        $x_1_2 = "/upload.php" ascii //weight: 1
        $x_1_3 = "/odcommand.php?clie\\cookies.sqlite" ascii //weight: 1
        $x_1_4 = "echo systeminfo:systeminfo >>1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

