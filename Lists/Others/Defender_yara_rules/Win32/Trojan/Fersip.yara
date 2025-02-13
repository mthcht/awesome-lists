rule Trojan_Win32_Fersip_A_2147691575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fersip.A"
        threat_id = "2147691575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fersip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "minersource\\Release\\bitcoin-miner.pdb" ascii //weight: 1
        $x_1_2 = "S3fmwfgdfwadaw33dDd" wide //weight: 1
        $x_1_3 = "msvcsip4.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

