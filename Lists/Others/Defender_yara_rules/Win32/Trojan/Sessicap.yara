rule Trojan_Win32_Sessicap_A_2147957190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Sessicap.A!dha"
        threat_id = "2147957190"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Sessicap"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pcdOpenSession" ascii //weight: 1
        $x_1_2 = {5c 41 64 6f 00 62 65 64 62 2e 64 61 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

