rule Worm_Win32_Framatizk_A_2147710281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Framatizk.A"
        threat_id = "2147710281"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Framatizk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FrmZita" ascii //weight: 1
        $x_1_2 = "TimerSpreadMe" ascii //weight: 1
        $x_1_3 = "x\\Zita.vbp" wide //weight: 1
        $x_1_4 = "open ftp.webcindario.com" wide //weight: 1
        $x_1_5 = "mget bpwd.zip" wide //weight: 1
        $x_1_6 = "exe.rerolpxE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

