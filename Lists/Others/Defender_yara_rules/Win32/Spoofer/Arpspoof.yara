rule Spoofer_Win32_Arpspoof_A_2147638412_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spoofer:Win32/Arpspoof.A"
        threat_id = "2147638412"
        type = "Spoofer"
        platform = "Win32: Windows 32-bit platform"
        family = "Arpspoof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 eb 14 ff d7 66 3d 50 00}  //weight: 1, accuracy: High
        $x_1_2 = {8a 48 0e 8d 70 0e 83 e1 0f 33 d2 57 8a 54 8e 0c 8d 2c 8e 66 8b 4e 02 8b fa c1 ef 04}  //weight: 1, accuracy: High
        $x_1_3 = "Hijack received %d packets" ascii //weight: 1
        $x_1_4 = "Tatol %d hosts" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

