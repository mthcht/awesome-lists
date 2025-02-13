rule Trojan_Win32_Ahrocam_A_2147632850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ahrocam.A"
        threat_id = "2147632850"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ahrocam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_uninsep.bat" ascii //weight: 1
        $x_1_2 = {72 62 00 00 73 76 63 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = "Mozilla/4.0 compatible; MSIE 6.0; Windows NT 5.1; SV1" wide //weight: 1
        $x_1_4 = {53 65 00 00 70 65 6e 52 65 71 75 65 73 74 41 00 48 74 74 70 4f 00 00 00 6e 65 74 43 6f 6e 6e 65 63 74 41 00 49 6e 74 65 72 00 00 00 72 6e 65 74 4f 70 65 6e 55 72 6c}  //weight: 1, accuracy: High
        $x_5_5 = {85 c9 75 08 0f be 06 83 e8 55 eb 15 0f be 44 31 ff 03 c1 bd 5f 00 00 00 99 f7 fd 0f be 04 31 2b c2 83 f8 20 7d 03 83 c0 5f 88 04 39 41 3b cb 7c cf c6 04 39 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

