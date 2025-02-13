rule Trojan_Win32_IISBackdoor_G_2147844765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/IISBackdoor.G"
        threat_id = "2147844765"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "IISBackdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bv+yAn=vtiP*avv" ascii //weight: 2
        $x_2_2 = "\\IIS_backdoor-master\\IIS_backdoor_dll\\obj\\Release\\ConnService.pdb" ascii //weight: 2
        $x_2_3 = "XorConvertBack" ascii //weight: 2
        $x_2_4 = "xorKeyBytes" ascii //weight: 2
        $x_2_5 = "IHttpModule" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

