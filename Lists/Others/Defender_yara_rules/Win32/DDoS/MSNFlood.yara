rule DDoS_Win32_MSNFlood_C_2147620185_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Win32/MSNFlood.C"
        threat_id = "2147620185"
        type = "DDoS"
        platform = "Win32: Windows 32-bit platform"
        family = "MSNFlood"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MSN Spammer" wide //weight: 1
        $x_1_2 = "\\syst32.exe" ascii //weight: 1
        $x_1_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 79 6e 2d 7a 79 73 63 2e 63 6f 6d 2f 73 68 61 6e 67 48 75 2f 50 53 59 2e 65 78 65 00 00 ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {2d 20 43 6f 6e 76 65 72 73 61 00 00 6c 6f 6c 6c 6c 6c 6c 20 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

