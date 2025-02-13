rule TrojanSpy_Win32_Posokap_A_2147708718_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Posokap.A!bit"
        threat_id = "2147708718"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Posokap"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4b 41 50 54 4f 58 41 00}  //weight: 1, accuracy: High
        $x_1_2 = "oscan process with pid for kartoxa" ascii //weight: 1
        $x_2_3 = {5c 6d 6d 6f 6e 2e 70 64 62 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

