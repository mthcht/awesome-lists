rule Trojan_Win32_Spywarex_EC_2147920192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Spywarex.EC!MTB"
        threat_id = "2147920192"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Spywarex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "homelock/spystatus" ascii //weight: 1
        $x_1_2 = "TIAN WANG GAI DI HU" ascii //weight: 1
        $x_1_3 = "homelock/lock" ascii //weight: 1
        $x_1_4 = "browser-home-locker" ascii //weight: 1
        $x_1_5 = "bholoader.win32.release.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

