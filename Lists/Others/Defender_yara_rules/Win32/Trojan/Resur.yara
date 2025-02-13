rule Trojan_Win32_Resur_LK_2147839037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Resur.LK!MTB"
        threat_id = "2147839037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Resur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "fscommand\\_fscmd_inst1.exe" ascii //weight: 10
        $x_10_2 = "Folder\\Equation\\Killer.exe" ascii //weight: 10
        $x_1_3 = "f50.exe" ascii //weight: 1
        $x_1_4 = "MouseLocator.EXE" ascii //weight: 1
        $x_1_5 = "plusone.google.com/_/+1/confirm?hl=en&url=http//efigureout.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

