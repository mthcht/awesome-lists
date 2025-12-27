rule Trojan_Win64_SleepyFileDeleter_A_2147951180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SleepyFileDeleter.A"
        threat_id = "2147951180"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SleepyFileDeleter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 48 89 e5 48 83 ec 40 48 c7 c1 10 27 00 00 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 89 c1 48 8d 55 f8 e8 ?? ?? ?? ?? 48 8b 48 08 e8 ?? ?? ?? ?? 48 c7 c1 00 00 00 00 e8}  //weight: 1, accuracy: Low
        $n_1_2 = {8b 85 50 26 00 00 83 e8 02 39 85 98 26 00 00 ?? ?? 8b 85 50 26 00 00 83 e8 02 48 8b 95 40 26 00 00 48 98 c6 04 02 00 48 8b 95 40 26 00 00 48 8b 85 78 26 00 00 48 89 c1 e8}  //weight: -1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win64_SleepyFileDeleter_B_2147951181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SleepyFileDeleter.B"
        threat_id = "2147951181"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SleepyFileDeleter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 83 ec 28 83 fa 01 75 ?? 48 c7 c1 10 27 00 00 e8 ?? ?? ?? ?? 48 83 c4 28 48 c7 c0 01 00 00 00 c3}  //weight: 1, accuracy: Low
        $n_1_2 = {8b 85 50 26 00 00 83 e8 02 39 85 98 26 00 00 ?? ?? 8b 85 50 26 00 00 83 e8 02 48 8b 95 40 26 00 00 48 98 c6 04 02 00 48 8b 95 40 26 00 00 48 8b 85 78 26 00 00 48 89 c1 e8}  //weight: -1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

