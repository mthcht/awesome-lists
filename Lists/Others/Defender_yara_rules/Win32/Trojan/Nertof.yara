rule Trojan_Win32_Nertof_A_2147716800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nertof.A"
        threat_id = "2147716800"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nertof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "185.14.185.38/google/point.php" wide //weight: 1
        $x_1_2 = "downloadfile('1L1','1F1');start-process rundll32.exe \"1C1" wide //weight: 1
        $x_1_3 = "2=BoT" wide //weight: 1
        $x_1_4 = "[PASSW FILES]" wide //weight: 1
        $x_1_5 = "[HUNTER FILES]" wide //weight: 1
        $x_1_6 = "0=102030@@#####" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

