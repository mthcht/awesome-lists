rule Backdoor_Win32_Rcontrole_2147731156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Rcontrole"
        threat_id = "2147731156"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Rcontrole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ubilseby.bat" ascii //weight: 1
        $x_1_2 = "/key.php?key=" ascii //weight: 1
        $x_1_3 = "/buffer.php?buffer=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

