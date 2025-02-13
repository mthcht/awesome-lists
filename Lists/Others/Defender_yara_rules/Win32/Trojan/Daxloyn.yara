rule Trojan_Win32_Daxloyn_A_2147625420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Daxloyn.A"
        threat_id = "2147625420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Daxloyn"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {4f 6e 6c 79 41 64 53 79 73 32 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6f 53 61 79 48 65 6c 6c 6f 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 3, accuracy: High
        $x_3_2 = ".ppt.pdg.mp3.mp4.wma.voc.mov.avi.mov.rm.rmvb.asf.mpeg.mpg.wmv.3gp.exe.rar" ascii //weight: 3
        $x_1_3 = "/update/hx" ascii //weight: 1
        $x_1_4 = "/update/OnlyAd" ascii //weight: 1
        $x_1_5 = {50 4f 50 55 52 4c 4c 49 53 54 00}  //weight: 1, accuracy: High
        $x_1_6 = {50 4f 50 50 52 4f 43 45 53 53 4e 41 4d 45 00}  //weight: 1, accuracy: High
        $x_1_7 = {50 4f 50 50 45 52 43 45 4e 54 00}  //weight: 1, accuracy: High
        $x_1_8 = {44 4f 57 4e 55 52 4c 00}  //weight: 1, accuracy: High
        $x_1_9 = {43 4c 49 43 4b 53 54 59 4c 45 00}  //weight: 1, accuracy: High
        $x_1_10 = {53 45 41 52 43 48 45 4e 54 52 59 55 52 4c 00}  //weight: 1, accuracy: High
        $x_1_11 = {4d 55 4c 55 52 4c 45 4e 41 42 4c 45 44 00}  //weight: 1, accuracy: High
        $x_1_12 = {50 76 50 6c 75 67 53 72 76 5f 53 69 6c 65 6e 63 65 5f 56 31 2e 64 6c 6c 00 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 44 6f 53 61 79 48 65 6c 6c 6f 00 53 65 72 76 69 63 65 4d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

