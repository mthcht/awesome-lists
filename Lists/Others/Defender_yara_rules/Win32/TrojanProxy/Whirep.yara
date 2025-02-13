rule TrojanProxy_Win32_Whirep_B_2147610979_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanProxy:Win32/Whirep.gen!B"
        threat_id = "2147610979"
        type = "TrojanProxy"
        platform = "Win32: Windows 32-bit platform"
        family = "Whirep"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 19 f6 45 fc 01 74 03 80 c3 f8 f6 45 fc 02 74 02 b3 4c f6 45 fc 04 74 02 b3 50 8a c3}  //weight: 1, accuracy: High
        $x_1_2 = {c7 45 fc 0a 00 00 00 c6 06 05 c6 46 03 01}  //weight: 1, accuracy: High
        $x_2_3 = {e8 0d 00 00 00 5c 73 79 73 72 65 73 74 2e 73 79 73 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

