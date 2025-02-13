rule Trojan_Win32_Colste_A_2147688291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Colste.A"
        threat_id = "2147688291"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Colste"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "*wallet*" wide //weight: 1
        $x_1_2 = "\\Dropbox\\Apps\\Blockchain.info\\" wide //weight: 1
        $x_1_3 = {41 88 04 32 83 f9 05 72 f1 8b c6 42 8d 78 01 8d 9b 00 00 00 00 8a 08 40 84 c9 75 f9 2b c7 3b d0 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

