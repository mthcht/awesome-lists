rule Worm_Win32_Rethed_A_2147689130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rethed.A"
        threat_id = "2147689130"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rethed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "first=1&data=%s*%s %s*%s*%s*%s" ascii //weight: 1
        $x_1_2 = "\\Ether\\Bin\\Ether.pdb" ascii //weight: 1
        $x_1_3 = "TZapCommunicator" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

