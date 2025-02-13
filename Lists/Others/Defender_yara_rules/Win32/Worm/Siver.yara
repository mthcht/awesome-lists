rule Worm_Win32_Siver_A_2147629569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Siver.A!dll"
        threat_id = "2147629569"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Siver"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyBoarddll-" ascii //weight: 1
        $x_1_2 = "Searchdll-" ascii //weight: 1
        $x_1_3 = "Transitdll-" ascii //weight: 1
        $x_1_4 = "ShareInfectdll-" ascii //weight: 1
        $x_1_5 = "[AutoRun]" ascii //weight: 1
        $x_1_6 = ":\\AutoRun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Worm_Win32_Siver_A_2147629579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Siver.gen!A"
        threat_id = "2147629579"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Siver"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 39 00 75 1c 8b 55 ?? 3b 55 ?? 75 09 c7 45 ?? 06 00 00 80 eb 09}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 04 24 c6 00 eb c6 40 01 ?? c2 04 00}  //weight: 1, accuracy: Low
        $x_2_3 = {74 a6 81 7d fc 27 03 00 00 75 47 eb 9b 3d 02 01 00 00}  //weight: 2, accuracy: High
        $x_1_4 = {8b 44 24 10 8d 0c 06 8b c6 99 f7 fb 8a 44 3a 04 30 01 46 3b 74 24 14 7c e7}  //weight: 1, accuracy: High
        $x_1_5 = {33 f6 56 6a 01 6a 02 ff 15 ?? ?? ?? ?? 6a 35 89 83 06 00 83 c7 08 4e 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

