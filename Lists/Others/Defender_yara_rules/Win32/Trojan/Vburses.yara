rule Trojan_Win32_Vburses_PL_2147636490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vburses.PL"
        threat_id = "2147636490"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vburses"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Program Files\\Microsoft Visual Studio\\VB98\\VB Projects\\Viruses\\HDKP4\\HDKP_4.vbp" wide //weight: 1
        $x_1_2 = "Say GoodBye To Your Hard Drive" wide //weight: 1
        $x_1_3 = "rem Author: Munga Bunga - from Australia, the land full of retarded Australian" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

