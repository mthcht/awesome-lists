rule PWS_Win32_Perfwef_A_2147599185_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Perfwef.gen!A"
        threat_id = "2147599185"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Perfwef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "StartHook" ascii //weight: 1
        $x_1_2 = "StopHook" ascii //weight: 1
        $x_1_3 = "ElementClient Window" ascii //weight: 1
        $x_1_4 = "EquipFunc" ascii //weight: 1
        $x_2_5 = {8d 45 b4 50 b9 05 00 00 00 66 ba 95 19 a1 ?? ?? ?? ?? e8}  //weight: 2, accuracy: Low
        $x_5_6 = {8b 55 fc 8a 54 3a ff 32 55 f3 8b 4d fc 8a 0c 39 2a d1 88 54 38 ff 47 4e 75 de}  //weight: 5, accuracy: High
        $x_5_7 = {8a 13 80 f2 ?? 88 54 38 ff 47 43 4e 75 ea}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

