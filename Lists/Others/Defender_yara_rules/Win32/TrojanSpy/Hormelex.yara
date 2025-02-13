rule TrojanSpy_Win32_Hormelex_D_2147684973_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Hormelex.D"
        threat_id = "2147684973"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Hormelex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "C15F91B86AD00A3AEB" ascii //weight: 10
        $x_10_2 = "http://systemjhockogyn.com.br/boa.php" ascii //weight: 10
        $x_1_3 = "to=neto9001ftp@gmail.com" ascii //weight: 1
        $x_1_4 = "subject=Montoya-PC" ascii //weight: 1
        $x_1_5 = "90AD6689AD6D934F3CE72FD2" ascii //weight: 1
        $x_1_6 = "628B42F022DD59C1B1558CAB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

