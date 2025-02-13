rule Trojan_Win32_Quilzir_A_2147605298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Quilzir.A"
        threat_id = "2147605298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Quilzir"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {b8 00 5c 26 05 e8 ?? ?? ?? ff 50 e8 ?? ?? ?? ff c3}  //weight: 3, accuracy: Low
        $x_1_2 = "fakenamegenerator.com/index.php?c=us&gen=random&n=us" wide //weight: 1
        $x_1_3 = ".com/em/s2.php?" wide //weight: 1
        $x_1_4 = ".com/em/email.php" ascii //weight: 1
        $x_1_5 = {00 5a 69 6c 6c 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

