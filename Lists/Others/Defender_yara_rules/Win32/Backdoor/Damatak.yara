rule Backdoor_Win32_Damatak_A_2147719635_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Damatak.A"
        threat_id = "2147719635"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Damatak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "winhost32.exe" ascii //weight: 1
        $x_1_2 = "zexplorer.exe" ascii //weight: 1
        $x_1_3 = "guid=%i64u&build=%s&info=%s&ip=%s&type=1&win=%d.%d(x" ascii //weight: 1
        $x_1_4 = {2e 63 66 67 00 00 00 00 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {68 74 74 70 3a 2f 2f 61 70 69 2e 69 70 69 66 79 2e 6f 72 67 00 00 00 00 30 2e 30 2e 30 2e 30}  //weight: 1, accuracy: High
        $x_1_6 = {75 12 83 7d f8 00 75 0c 8b 4d f0 51 e8 ?? ?? ?? ?? 83 c4 04 83 7d e8 00 75 02 eb 02 eb}  //weight: 1, accuracy: Low
        $x_1_7 = {8b 4f 10 33 c0 85 c9 74 09 80 34 30 a1 40 3b c1 72 f7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

