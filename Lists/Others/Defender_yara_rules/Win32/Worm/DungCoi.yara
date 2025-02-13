rule Worm_Win32_DungCoi_PA_2147741407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/DungCoi.PA!MTB"
        threat_id = "2147741407"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "DungCoi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\system32\\NWB.dat" wide //weight: 2
        $x_2_2 = "http://dungcoivb.googlepages.com/NWB.txt" wide //weight: 2
        $x_2_3 = "C:\\PNga.txt" wide //weight: 2
        $x_2_4 = "Chuc mung, ban da tam thoi thoat khoi Worm DungCoi" wide //weight: 2
        $x_1_5 = "yahoobuddymain" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

