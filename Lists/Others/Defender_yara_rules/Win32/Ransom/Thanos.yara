rule Ransom_Win32_Thanos_A_2147753804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Thanos.A!MTB"
        threat_id = "2147753804"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Thanos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".encrypted" wide //weight: 1
        $x_1_2 = ".locked" wide //weight: 1
        $x_1_3 = "You should receive a little punishment" wide //weight: 1
        $x_2_4 = "EncryptFile" ascii //weight: 2
        $x_2_5 = "CyberThanos.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

