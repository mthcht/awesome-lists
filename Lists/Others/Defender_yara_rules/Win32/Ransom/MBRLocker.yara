rule Ransom_Win32_MBRLocker_A_2147723438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MBRLocker.A!bit"
        threat_id = "2147723438"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MBRLocker"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\\\.\\\\physicaldrive0" ascii //weight: 10
        $x_10_2 = "Your computer is locked" ascii //weight: 10
        $x_3_3 = "wwe100" ascii //weight: 3
        $x_2_4 = {6a 00 6a 00 6a 00 56 ff 15 ?? ?? ?? ?? 6a 00 8d 45 f4 50 68 00 02 00 00 68 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 56 ff 15}  //weight: 2, accuracy: Low
        $x_1_5 = {32 54 05 f4 40 3b c1 7c f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_MBRLocker_DA_2147772135_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MBRLocker.DA!MTB"
        threat_id = "2147772135"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MBRLocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "your windows will die from covid21 corona virus" ascii //weight: 1
        $x_1_2 = "covid21 is here! your windows will be destroyed" ascii //weight: 1
        $x_1_3 = "corona.vbs" ascii //weight: 1
        $x_1_4 = "PayloadMBR.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

