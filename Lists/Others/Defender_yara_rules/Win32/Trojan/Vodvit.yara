rule Trojan_Win32_Vodvit_B_2147650983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vodvit.B"
        threat_id = "2147650983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vodvit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b2 6c b3 6f b9 34 00 00 00 33 c0 8d bc 24 ?? ?? ?? ?? 88 94 24 ?? ?? ?? ?? 88 94 24 ?? ?? ?? ?? c6 84 24 ?? ?? ?? ?? 64}  //weight: 1, accuracy: Low
        $x_1_2 = "au_updata.exe" ascii //weight: 1
        $x_1_3 = "aucode_1992_0915" ascii //weight: 1
        $x_1_4 = "aulist.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

