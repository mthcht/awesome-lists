rule TrojanClicker_Win32_Towshin_A_2147624769_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Towshin.A"
        threat_id = "2147624769"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Towshin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 00 69 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 76 00 62 00 70 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "/lijiang.asp?s=" wide //weight: 1
        $x_1_3 = "tfol.com,vnet.cn,cnbb.com.cn,opendns.com" wide //weight: 1
        $x_1_4 = {00 00 64 00 6f 00 77 00 73 00 5c 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

