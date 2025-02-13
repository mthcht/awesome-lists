rule Trojan_Win32_Shizpusik_A_2147740707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shizpusik.A"
        threat_id = "2147740707"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shizpusik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".dll.exedownload.windowsupdate.com" ascii //weight: 1
        $x_1_2 = "HTTP/1.1https://http://%s" ascii //weight: 1
        $x_1_3 = "[%u][%s:%s:%u][0x%x;0x%x] %sDnsFlushResolverCache" ascii //weight: 1
        $x_1_4 = {33 d2 88 14 03 3b da 76 47}  //weight: 1, accuracy: High
        $x_1_5 = "project\\main\\payload\\payload.x86.pdb" ascii //weight: 1
        $x_1_6 = {55 00 53 00 45 00 52 00 5f 00 50 00 52 00 49 00 56 00 5f 00 47 00 55 00 45 00 53 00 54 00 [0-16] 55 00 53 00 45 00 52 00 5f 00 50 00 52 00 49 00 56 00 5f 00 55 00 53 00 45 00 52 00 [0-16] 55 00 53 00 45 00 52 00 5f 00 50 00 52 00 49 00 56 00 5f 00 41 00 44 00 4d 00 49 00 4e 00 [0-16] 25 00 77 00 73 00 5c 00 25 00 77 00 73 00}  //weight: 1, accuracy: Low
        $x_3_7 = {b2 f8 f0 f0 b2 f9 e4 f9 f8 f3 eb f2 f0 f3 fd f8 b2 eb f5 f2 f8 f3 eb ef e9 ec f8 fd e8 f9 b2 ff}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

