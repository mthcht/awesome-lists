rule Trojan_Win32_Chenf_A_2147686313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Chenf.A"
        threat_id = "2147686313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Chenf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "spe" wide //weight: 1
        $x_1_2 = "google_guid.dat" ascii //weight: 1
        $x_1_3 = {6a 00 61 00 76 00 61 00 32 00 2e 00 65 00 78 00 65}  //weight: 1, accuracy: High
        $x_1_4 = "deleteself" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

