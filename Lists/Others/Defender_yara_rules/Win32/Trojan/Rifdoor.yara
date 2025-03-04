rule Trojan_Win32_RifDoor_EC_2147892161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RifDoor.EC!MTB"
        threat_id = "2147892161"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RifDoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rifle.pdb" ascii //weight: 1
        $x_1_2 = "guifx.exe\" /run" ascii //weight: 1
        $x_1_3 = "DeleteUrlCacheEntry" ascii //weight: 1
        $x_1_4 = "$downloadexec" ascii //weight: 1
        $x_1_5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_6 = "/c del /q" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

