rule Trojan_Win32_Tavsurv_A_2147928038_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tavsurv.A!dha"
        threat_id = "2147928038"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tavsurv"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {30 07 83 c7 01 83 c5 01 3b 6c 24 28 7c bb}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

