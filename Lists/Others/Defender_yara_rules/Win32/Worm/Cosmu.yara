rule Worm_Win32_Cosmu_B_2147633055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Cosmu.B"
        threat_id = "2147633055"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Cosmu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TAPIxForm" ascii //weight: 1
        $x_1_2 = "set SER=ftp.sakunia" ascii //weight: 1
        $x_1_3 = ">> upl.txt" ascii //weight: 1
        $x_1_4 = {2e 6a 70 67 2e 65 78 65 00 00 66 3a 2f [0-16] 2e 6a 70 67 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

