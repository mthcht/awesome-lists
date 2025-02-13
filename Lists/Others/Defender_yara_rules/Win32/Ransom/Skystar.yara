rule Ransom_Win32_Skystar_EA_2147853199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Skystar.EA!MTB"
        threat_id = "2147853199"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Skystar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_2 = "notepad C:\\SKYSTARSRANSOMWARE.txt" ascii //weight: 1
        $x_1_3 = "blackmoon" ascii //weight: 1
        $x_1_4 = "SkystarsDefender" ascii //weight: 1
        $x_1_5 = "myapp.exe.SKYSTARS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

