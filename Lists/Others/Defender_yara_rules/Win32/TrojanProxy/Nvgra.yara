rule TrojanProxy_Win32_Nvgra_A_2147609446_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Nvgra.gen!A"
        threat_id = "2147609446"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Nvgra"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {75 27 83 bd 7c ff ff ff 7c 75 1e b9 1f 00 00 00 8d 75 84 8b 7d 08 f3 a5}  //weight: 1, accuracy: High
        $x_1_2 = {8b 55 fc 33 c0 8a 42 02 83 f8 05 75 16 8b 4d fc 8b 51 04 89 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

