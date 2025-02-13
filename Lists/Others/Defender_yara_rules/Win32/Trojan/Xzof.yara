rule Trojan_Win32_Xzof_A_2147678615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Xzof.A"
        threat_id = "2147678615"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Xzof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 70 01 90 8a 10 40 84 d2 75 f9 2b c6 3b c8 7c e3 b8}  //weight: 1, accuracy: High
        $x_1_2 = {eb 06 8d 9b 00 00 00 00 0f b6 4c 34 34 51 8d 54 24 20 68}  //weight: 1, accuracy: High
        $x_1_3 = {66 6f 7a 78 00}  //weight: 1, accuracy: High
        $x_1_4 = "]XJOEPXT" ascii //weight: 1
        $x_1_5 = "]Ufnq" ascii //weight: 1
        $x_1_6 = "dszq/qiq" ascii //weight: 1
        $x_1_7 = "cryp.php" ascii //weight: 1
        $x_1_8 = "ti4mmzqvol/dpn" ascii //weight: 1
        $x_1_9 = "sh3llypunk.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

