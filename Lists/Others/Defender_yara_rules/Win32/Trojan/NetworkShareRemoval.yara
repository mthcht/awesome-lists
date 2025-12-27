rule Trojan_Win32_NetworkShareRemoval_A_2147950523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/NetworkShareRemoval.A"
        threat_id = "2147950523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "NetworkShareRemoval"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 65 00 74 00 [0-8] 20 00 75 00 73 00 65 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = " /delete" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

