rule TrojanSpy_Win32_Komilet_A_2147728359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Komilet.A!bit"
        threat_id = "2147728359"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Komilet"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Bitcoin\\wallets\\*.dat" ascii //weight: 1
        $x_1_2 = "Cookies\\Kometa_Cookies.txt" ascii //weight: 1
        $x_1_3 = "%s\\Mozilla\\Firefox\\profiles.ini" ascii //weight: 1
        $x_1_4 = "http://185.219.81.232/Upload/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

