rule Trojan_Win32_Calelk_A_2147632783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Calelk.A"
        threat_id = "2147632783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Calelk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 fa 10 75 02 33 d2 ac 32 82 ?? ?? ?? ?? aa 42 49 75 ed}  //weight: 1, accuracy: Low
        $x_1_2 = {6a 09 6a 01 6a 6c 6a 00 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

