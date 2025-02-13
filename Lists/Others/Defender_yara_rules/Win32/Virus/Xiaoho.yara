rule Virus_Win32_Xiaoho_2147609933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Xiaoho"
        threat_id = "2147609933"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Xiaoho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "XiaoHao Microsoft" wide //weight: 2
        $x_2_2 = "CWormBegin" ascii //weight: 2
        $x_2_3 = "shellexecute=Xiaohao.exe" ascii //weight: 2
        $x_2_4 = "shell\\Auto\\command=Xiaohao.exe" ascii //weight: 2
        $x_2_5 = "X14o-H4o's Virus" ascii //weight: 2
        $x_2_6 = {6f 70 65 6e 3d 58 69 61 6f 68 61 6f 2e 65 78 65 0d 0a 00 00 5b 41 75 74 6f 72 75 6e 5d}  //weight: 2, accuracy: High
        $x_2_7 = "iframe src=http://xiaohao.yona.biz/xiaohao.htm" ascii //weight: 2
        $x_1_8 = "c:\\Jilu.txt" ascii //weight: 1
        $x_1_9 = "SOFTWARE\\Microsoft\\Active Setup\\Installed Components\\{H9I12RB03-AB-B70-7-11d2-9CBD-0O00FS7AH6-9E2121BHJLK}" ascii //weight: 1
        $x_2_10 = {8b 35 f0 12 40 00 57 6a 01 8d 45 b4 6a 40 50 ff d6 83 c4 10 66 81 7d b4 4d 5a 75 e0 6a 00 ff 75 f0 57 ff 15 ec 12 40 00 57 6a 01 8d 85 bc fe ff ff 68 f8 00 00 00 50 ff d6 83 c4 1c 81 bd bc fe ff ff 50 45 00 00 75 05 6a 01 5e eb 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

