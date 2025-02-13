rule Ransom_Win32_Molock_A_2147716337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Molock.A!bit"
        threat_id = "2147716337"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Molock"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 06 00 00 00 8b 5d f8 e8 ?? ?? ?? ?? 53 68 01 00 00 00 68 04 00 00 00 68 1a 02 00 c0 b8 0a 00 00 00 e8 ?? ?? ?? ?? 39 65 f4 74 0d 68 06 00 00 00 e8}  //weight: 1, accuracy: Low
        $x_1_2 = "NtRaiseHardError" ascii //weight: 1
        $x_1_3 = "\\\\physicaldrive0" ascii //weight: 1
        $x_1_4 = "Your disk have a lock!Please input the unlock password!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Win32_Molock_MAK_2147794242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Molock.MAK!MTB"
        threat_id = "2147794242"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Molock"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Your disk have a lock!Please input the unlock password!" ascii //weight: 10
        $x_1_2 = "\\physicaldrive0" ascii //weight: 1
        $x_1_3 = "port:" ascii //weight: 1
        $x_1_4 = "ip / host:" ascii //weight: 1
        $x_1_5 = "mailto:" ascii //weight: 1
        $x_1_6 = "shell\\open\\command" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

