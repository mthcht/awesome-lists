rule Worm_Win32_Rathsomm_A_2147625716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Rathsomm.A"
        threat_id = "2147625716"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Rathsomm"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {89 85 78 ff ff ff 83 bd 78 ff ff ff 6e 74 0e 83 bd 78 ff ff ff 15 74 05 e9}  //weight: 2, accuracy: High
        $x_2_2 = {7d 7d 8b 45 80 89 04 24 e8 ?? ?? ?? ?? 83 ec 04 83 f8 02 75 57}  //weight: 2, accuracy: Low
        $x_2_3 = {66 85 c0 74 31 83 bd e4 fb ff ff 00 79 28 83 bd e0 f6 ff ff 40 7e 1f 83 bd e0 f6 ff ff 5a 7f 16}  //weight: 2, accuracy: High
        $x_1_4 = ".php?name=%NAME%&guid=%GUID%&log=%LOG%" ascii //weight: 1
        $x_1_5 = "[Steam] Username=" ascii //weight: 1
        $x_1_6 = "[SNIFF] TYPE=" ascii //weight: 1
        $x_1_7 = "[KEYLOG] WND=" ascii //weight: 1
        $x_1_8 = "[HTTP] RAW=" ascii //weight: 1
        $x_1_9 = "%sautorun.inf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

