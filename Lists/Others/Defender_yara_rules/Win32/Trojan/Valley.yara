rule Trojan_Win32_Valley_MK_2147974738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Valley.MK!MTB"
        threat_id = "2147974738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Valley"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "High"
    strings:
        $x_15_1 = {c1 f0 9e 81 d9 ad d1 a3 9b c1 c9 02 c1 f2 a2 66 c1 b4 04 00 00 00 80 0b 66 81 c2 18 3a f7 d1 8d 8c 11 db 8f 8c ba 33 d9 66 c1 84 04 01 00 00 80 26 03 e9 c1 f8 ad}  //weight: 15, accuracy: High
        $x_10_2 = "\\\\.\\Warsaw_PM" wide //weight: 10
        $x_5_3 = "cmd.exe /c start \"\" /B cmd /C %s" wide //weight: 5
        $x_3_4 = "taskkill /f /im cmd.exe" wide //weight: 3
        $x_2_5 = "1EBE7ED7C9372896C3C28E541588DD12A08B24BA6BC3CEB699FCA838443886C6" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

