rule Trojan_Win32_Hider_2147595281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Hider"
        threat_id = "2147595281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Hider"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CeylonSpyNetXp" ascii //weight: 2
        $x_2_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\SuperHidden" ascii //weight: 2
        $x_2_3 = "CSNetManagerXp" ascii //weight: 2
        $x_2_4 = "isass.exe" ascii //weight: 2
        $x_2_5 = "Downloaded Video Files.exe" ascii //weight: 2
        $x_1_6 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

