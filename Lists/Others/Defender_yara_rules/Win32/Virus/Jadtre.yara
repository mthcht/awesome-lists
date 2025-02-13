rule Virus_Win32_Jadtre_A_2147632742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Jadtre.gen!A"
        threat_id = "2147632742"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Jadtre"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b ff 55 a1 ?? ?? ?? ?? 83 c0 03 ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c4 10 0f be 05 ?? ?? ?? ?? 83 f8 92 75 16}  //weight: 1, accuracy: Low
        $x_2_3 = {c7 40 24 20 00 00 e0 8b 45 ?? 8b 0d ?? ?? ?? ?? 66 8b 09 66 89 48 22}  //weight: 2, accuracy: Low
        $x_1_4 = "\\\\.\\pipe\\96DBA249-E88E-4c47-98DC-E18E6E3E3E5A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

