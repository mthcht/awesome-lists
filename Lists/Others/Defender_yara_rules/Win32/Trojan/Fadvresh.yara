rule Trojan_Win32_Fadvresh_A_2147648479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fadvresh.A"
        threat_id = "2147648479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fadvresh"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "http://none.none.none" ascii //weight: 1
        $x_1_2 = "AdvRefresh" ascii //weight: 1
        $x_1_3 = {be 4e 02 00 00 3b d6 7e ?? 8b d6 89 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

