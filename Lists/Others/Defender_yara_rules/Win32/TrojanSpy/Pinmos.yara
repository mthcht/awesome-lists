rule TrojanSpy_Win32_Pinmos_A_2147654051_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Pinmos.A"
        threat_id = "2147654051"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Pinmos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" ascii //weight: 1
        $x_1_2 = "CryptUnprotectData" ascii //weight: 1
        $x_1_3 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_4 = "monitor?sid=" ascii //weight: 1
        $x_1_5 = "affiliat" ascii //weight: 1
        $x_1_6 = "login.icq.com" ascii //weight: 1
        $x_4_7 = {ff 46 0c 8b 45 f8 8b 08 85 c9 74 12 8b c1 33 d2 52 50 8b 46 04}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

