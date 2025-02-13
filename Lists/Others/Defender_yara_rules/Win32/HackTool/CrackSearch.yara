rule HackTool_Win32_CrackSearch_A_2147515165_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/CrackSearch.A"
        threat_id = "2147515165"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "CrackSearch"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "The Next Generation Search Engine ;-)" wide //weight: 1
        $x_1_2 = "YouKing 2005" wide //weight: 1
        $x_1_3 = "proxy.txt" ascii //weight: 1
        $x_1_4 = "CoversAll" ascii //weight: 1
        $x_1_5 = "CracksAll" ascii //weight: 1
        $x_1_6 = "SerialsAll" ascii //weight: 1
        $x_1_7 = "dreamcast" ascii //weight: 1
        $x_1_8 = "gamecube" ascii //weight: 1
        $x_1_9 = "Extended Module:" ascii //weight: 1
        $x_1_10 = "CraagleUtils" ascii //weight: 1
        $x_1_11 = "Proxy:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

