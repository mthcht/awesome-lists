rule TrojanSpy_Win32_Fastpos_A_2147728837_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Fastpos.A!bit"
        threat_id = "2147728837"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Fastpos"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s//cdosys.php" wide //weight: 1
        $x_1_2 = "keylog&log=WND%sKBD%s" wide //weight: 1
        $x_1_3 = "newcomputer&username=%S&computername=%S&os=%S&architecture=%S" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

