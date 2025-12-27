rule Trojan_Win64_NerdySponge_A_2147955642_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/NerdySponge.A!dha"
        threat_id = "2147955642"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "NerdySponge"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShutdownSQLProcesses" ascii //weight: 1
        $x_1_2 = "7992209782:AAGGIq74uLvUAS0kO8zUsKMGIJnCpGfg8w8" ascii //weight: 1
        $x_1_3 = "Failed to walk path %s: %v" ascii //weight: 1
        $x_1_4 = {f0 9f 93 b8 20 53 63 72 65 65 6e 73 68 6f 74 0a f0 9f 91 a4 20 55 73 65 72 3a 20 25 73 0a f0 9f 92 bb 20 43 6f 6d 70 75 74 65 72 3a 20 25 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

