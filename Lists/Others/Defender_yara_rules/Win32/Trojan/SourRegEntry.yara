rule Trojan_Win32_SourRegEntry_A_2147773982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SourRegEntry.A!dha"
        threat_id = "2147773982"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SourRegEntry"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\regentry.pdb" ascii //weight: 2
        $x_2_2 = "msqrvc.exe" ascii //weight: 2
        $x_1_3 = "C:\\LICENSE.TXT" ascii //weight: 1
        $x_1_4 = "C:\\Documents and Settings\\*" ascii //weight: 1
        $x_1_5 = "\\SystemVolumeInformation.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

