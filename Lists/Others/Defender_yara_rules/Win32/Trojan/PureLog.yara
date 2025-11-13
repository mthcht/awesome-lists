rule Trojan_Win32_PureLog_B_2147957466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PureLog.B!AMTB"
        threat_id = "2147957466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PureLog"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://poolfreshstep.com/enchantress" ascii //weight: 1
        $x_1_2 = "Arlai.pdb" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

