rule TrojanDropper_Win32_Silly_P2P_B_2147617931_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Silly_P2P.B"
        threat_id = "2147617931"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Silly_P2P"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d09f2340818511d396f6aaf844c7e325" ascii //weight: 1
        $x_1_2 = "52F260023059454187AF826A3C07AF2A" ascii //weight: 1
        $x_1_3 = ":\\autorun.inf" ascii //weight: 1
        $x_1_4 = ".com/ul.htm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

