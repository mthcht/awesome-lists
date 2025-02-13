rule Trojan_Win32_Flakdat_A_2147694816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Flakdat.A"
        threat_id = "2147694816"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Flakdat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 c0 03 00 00 3d 00 e0 01 00 75 ed}  //weight: 1, accuracy: High
        $x_1_2 = {52 75 6e 00 5c 00 2e 65 78 65 00 00 00 00 73 79 73 63 6f 6e 66 73 72 76 33 32}  //weight: 1, accuracy: High
        $x_1_3 = {24 21 52 51 00 00 21 24 00 24 21 52 46}  //weight: 1, accuracy: High
        $x_1_4 = "\\fkl.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

