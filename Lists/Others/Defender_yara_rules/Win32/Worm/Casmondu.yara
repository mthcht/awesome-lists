rule Worm_Win32_Casmondu_A_2147643710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Casmondu.A"
        threat_id = "2147643710"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Casmondu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "MyMoney.vbp" wide //weight: 1
        $x_1_2 = "usercash.com" wide //weight: 1
        $x_1_3 = {47 00 61 00 72 00 64 00 65 00 6e 00 44 00 65 00 66 00 65 00 6e 00 73 00 65 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 [0-51] 3a 00 5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00}  //weight: 1, accuracy: Low
        $x_1_4 = "tmrInfect" ascii //weight: 1
        $x_1_5 = "tmrMoney" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

