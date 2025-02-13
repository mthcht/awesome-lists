rule Trojan_Win32_Fuliban_A_2147705981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fuliban.A"
        threat_id = "2147705981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fuliban"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fulipao.com/sou.php?moban=3" ascii //weight: 1
        $x_1_2 = "/fulipao_banben.php" ascii //weight: 1
        $x_1_3 = "2345.com/?kweige" ascii //weight: 1
        $x_1_4 = {68 61 6f 31 32 33 5f 90 02 10 2e 65 78 65 00 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c 53 74 61 72 74 20 50 61 67 65}  //weight: 1, accuracy: High
        $x_1_5 = ".lesouwuguojie.com/jiqing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

