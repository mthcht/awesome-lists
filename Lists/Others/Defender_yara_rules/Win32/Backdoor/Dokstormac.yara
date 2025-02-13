rule Backdoor_Win32_Dokstormac_A_2147655245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Dokstormac.A"
        threat_id = "2147655245"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Dokstormac"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "49"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {00 7b 41 52 43 4f 4d 5f}  //weight: 20, accuracy: High
        $x_10_2 = "Video Capture" wide //weight: 10
        $x_10_3 = {42 61 6e 6b 4c 61 62 65 6c 3d 25 73 0d 0a 43 61 70 61 63 69 74 79 3d 25 73}  //weight: 10, accuracy: High
        $x_3_4 = {42 6f 6f 74 75 70 53 74 61 74 65 3d 25 73 0d 0a 44 4e 53 48 6f 73 74 4e 61 6d 65 3d 25 73}  //weight: 3, accuracy: High
        $x_3_5 = {44 65 76 69 63 65 49 44 3d 25 73 0d 0a 45 73 74 69 6d 61 74 65 64 43 68 61 72 67 65 52 65 6d 61 69 6e 69 6e 67 3d 25 73}  //weight: 3, accuracy: High
        $x_3_6 = {4d 65 6d 6f 72 79 54 79 70 65 3d 25 73 0d 0a 53 65 72 69 61 6c 4e 75 6d 62 65 72 3d 25 73}  //weight: 3, accuracy: High
        $x_3_7 = "InetCpl.cpl,ClearMyTracksByProcess 32" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_10_*) and 3 of ($x_3_*))) or
            (all of ($x*))
        )
}

