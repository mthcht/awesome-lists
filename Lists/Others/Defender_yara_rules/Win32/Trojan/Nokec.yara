rule Trojan_Win32_Nokec_A_2147627656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nokec.A"
        threat_id = "2147627656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nokec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "plugin/script_n.php?code=" ascii //weight: 1
        $x_1_2 = "go/count.php?go=" ascii //weight: 1
        $x_1_3 = {69 66 20 65 78 69 73 74 20 22 00}  //weight: 1, accuracy: High
        $x_1_4 = {6b 6f 64 65 63 00}  //weight: 1, accuracy: High
        $x_1_5 = {4d 6f 7a 69 6c 6c 61 57 69 6e 64 6f 77 43 6c 61 73 73 00 00 ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

