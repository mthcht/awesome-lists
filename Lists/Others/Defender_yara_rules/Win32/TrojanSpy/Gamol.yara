rule TrojanSpy_Win32_Gamol_A_2147692225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Gamol.A"
        threat_id = "2147692225"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Gamol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GamePlaza.exe" ascii //weight: 1
        $x_1_2 = "at=getmb&s13=%s" ascii //weight: 1
        $x_1_3 = "zq=%s&zf=%s&zu=%s&zp=%s&zmz=%s&l=%d&zjb=%d&zcj=%d&zck=%s&pin=%s&zzb=%s&para=%s&bsmb=%d&d20=%s:%s %s:%s %s:%s&hsn=%s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

