rule Trojan_Win32_Rifdoor_RA_2147830301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rifdoor.RA!MTB"
        threat_id = "2147830301"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rifdoor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Troy Source Code\\tcp1st\\rifle\\Release\\rifle.pdb" ascii //weight: 1
        $x_1_2 = "C:\\ProgramData\\Update\\wuauclt.exe" ascii //weight: 1
        $x_1_3 = "MUTEX394039_4930023" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

