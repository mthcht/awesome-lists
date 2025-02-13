rule Trojan_Win32_Jupealer_2147768781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Jupealer!MSR"
        threat_id = "2147768781"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Jupealer"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://45.146.165.222/j/post" wide //weight: 2
        $x_2_2 = "<steal_passwords>" ascii //weight: 2
        $x_1_3 = "\\AppData\\Roaming\\solarmarker.dat" wide //weight: 1
        $x_1_4 = "\\AppData\\Local\\Google\\Chrome\\User Data" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

