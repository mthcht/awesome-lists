rule Backdoor_Win32_Nethief_Y_2147622857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nethief.Y"
        threat_id = "2147622857"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nethief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nethief-callboard/Net" ascii //weight: 1
        $x_1_2 = "Nethief is testing...!" ascii //weight: 1
        $x_1_3 = "Nethief_Server" ascii //weight: 1
        $x_1_4 = "Nethief_Connect." ascii //weight: 1
        $x_1_5 = "Nethief_Notify." ascii //weight: 1
        $x_1_6 = "hief_Server -" ascii //weight: 1
        $x_1_7 = "del Nethief" ascii //weight: 1
        $x_1_8 = "thief_Callboard.dat" ascii //weight: 1
        $x_1_9 = "thief_Version.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_Win32_Nethief_AA_2147623650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nethief.AA"
        threat_id = "2147623650"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nethief"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c9 ff 33 c0 83 c4 08 f2 ae f7 d1 2b f9 6a 00 8b c1 8b f7 8b fa 68 80 00 00 00 c1 e9 02 f3 a5 8b c8 6a 03 83 e1 03 6a 00 f3 a4 6a 01 8d 8c 24 8c ?? ?? ?? 68 00 00 00 80 51}  //weight: 10, accuracy: Low
        $x_5_2 = "Make.cfg" ascii //weight: 5
        $x_5_3 = "RemoteComputer.exe" ascii //weight: 5
        $x_1_4 = "787EFFF5-E90D-45b6-B9CF-B751FE6E8252" ascii //weight: 1
        $x_1_5 = "6F9852E6-D501-4ffe-B065-F57C3F7B9870" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Nethief_AA_2147623651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Nethief.AA!dll"
        threat_id = "2147623651"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Nethief"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "iipConnectServer" ascii //weight: 10
        $x_10_2 = "IIPClient.dll" ascii //weight: 10
        $x_10_3 = "iipInstallCallbac" ascii //weight: 10
        $x_1_4 = {c7 46 04 01 00 00 00 89 08 8b 4c 24 18 89 50 04 8b 54 24 1c 89 48 08 8b 4c 24 20 89 50 0c 8b 44 24 24 8b 54 24 0c 50 51 52 ff 15 ?? ?? ?? ?? 83 c4 10}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 4e 1c 8b 56 18 51 8b 4c 24 2c 52 8b 54 24 2c 51 8b 4c 24 2c 52 51 53 8b c8 e8 ?? ?? ?? ?? b8 01 00 00 00 8b 4c 24 0c 64 89 0d 00 00 00 00 5f 5e 5b 83 c4 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

