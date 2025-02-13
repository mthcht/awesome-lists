rule Trojan_Win32_Pikboclick_A_2147679020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pikboclick.A"
        threat_id = "2147679020"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pikboclick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Pike.Pike-PC\\Desktop\\Desktop\\Bot Clicker\\Project1.vbp" wide //weight: 2
        $x_1_2 = "User-Agent: Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.7 (KHTML, like Gecko) RockMelt/" wide //weight: 1
        $x_1_3 = {76 00 61 00 72 00 20 00 41 00 64 00 4c 00 69 00 6e 00 6b 00 33 00 20 00 3d 00 20 00 22 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

