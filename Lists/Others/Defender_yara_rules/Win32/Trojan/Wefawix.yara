rule Trojan_Win32_Wefawix_A_2147636904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wefawix.A"
        threat_id = "2147636904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wefawix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ba 33 01 00 00 89 d1 83 ec 0c 99 f7 f9 56 8b 1c 95}  //weight: 1, accuracy: High
        $x_1_2 = {83 fb 46 5a 74 12 eb df 83 ec 0c 68 f4 01 00 00 e8}  //weight: 1, accuracy: High
        $x_1_3 = {ba ff 00 00 00 89 d1 83 c4 0c 99 f7 f9 0f be d2 68 00 20 03 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

