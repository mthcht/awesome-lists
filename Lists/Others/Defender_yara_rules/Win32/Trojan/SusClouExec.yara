rule Trojan_Win32_SusClouExec_A_2147930887_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SusClouExec.A"
        threat_id = "2147930887"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SusClouExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 [0-16] 2f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_2 = "powershell" wide //weight: 1
        $x_1_3 = "wget" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 [0-80] 2e 00 63 00 6c 00 6f 00 75 00 64 00 2d 00 78 00 69 00 70 00 2e 00 69 00 6f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

