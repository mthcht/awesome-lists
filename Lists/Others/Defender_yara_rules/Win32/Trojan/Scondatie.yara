rule Trojan_Win32_Scondatie_A_2147656054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Scondatie.A"
        threat_id = "2147656054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Scondatie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "111"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "DMTOOL" ascii //weight: 100
        $x_10_2 = "Files\\a\\synec.txt" ascii //weight: 10
        $x_10_3 = "Meetings\\a\\synec.exe" ascii //weight: 10
        $x_1_4 = {78 69 61 6e 67 78 69 2e 03 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = "jpgtu.dat" ascii //weight: 1
        $x_1_6 = "haotu.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((1 of ($x_100_*) and 2 of ($x_10_*))) or
            (all of ($x*))
        )
}

