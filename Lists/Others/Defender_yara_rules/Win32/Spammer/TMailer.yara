rule Spammer_Win32_TMailer_A_2147720965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/TMailer.A"
        threat_id = "2147720965"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "TMailer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "582822@qq.com" wide //weight: 1
        $x_1_2 = {5c 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 5c 00 52 00 75 00 6e 00 5c 00 [0-40] 2f 00 71 00 71 00 2e 00 70 00 68 00 70 00 3f 00 71 00 69 00 64 00 3d 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 00 6d 00 61 00 69 00 6c 00 2f 00 [0-8] 2e 00 74 00 78 00 74 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

