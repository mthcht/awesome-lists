rule Trojan_Win32_Phonzy_GVA_2147936970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Phonzy.GVA!MTB"
        threat_id = "2147936970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Phonzy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {32 d3 81 ff 14 47 ee 21 80 f2 41 32 c2 80 ea 26 0f 91 c0 98 d0 ca fe ca 66 0f ba f8 94 66 1d 12 3a 80 f2 fe 66 b8 0d 7c 02 e1 d2 c8 80 ea 37 8b c5 32 da 89 0c 14 66 81 fb be 6b}  //weight: 3, accuracy: High
        $x_2_2 = {32 c3 04 5d ba 4d 12 81 73 f9 d0 c0 2c 92 0f 9c c6 d0 c8 f8 f6 d8 66 0f b3 f2 fe ca d3 da 2c e2 66 f7 d2 32 d8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

