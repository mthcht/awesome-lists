rule TrojanSpy_Win32_Browken_A_2147734587_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Browken.A!bit"
        threat_id = "2147734587"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Browken"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " = OBJCREATE ( \"WinHttp.WinHttpRequest.5.1\" )" wide //weight: 1
        $x_1_2 = ".Open ( \"Post\" , \"https://iplogger.org/1Lhk57\" , FALSE )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

