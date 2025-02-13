rule PWS_Win32_Peerfit_A_2147631231_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Peerfit.A"
        threat_id = "2147631231"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Peerfit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 ff 4d e4 0f 85 22 ff ff ff 8d 45 e8 e8 ?? ?? ?? ?? 8b 46 08 8b 40 08 48}  //weight: 1, accuracy: Low
        $x_1_2 = "log in to your Gmail" ascii //weight: 1
        $x_1_3 = "B4E8D16C26323D4A" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Peerfit_A_2147631232_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Peerfit.gen!A"
        threat_id = "2147631232"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Peerfit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7d f0 00 74 08 8b 45 f0 e8 ?? ?? ?? ?? 33 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {8b 40 50 50 6a 00 6a ff e8 ?? ?? ?? ?? 8b f0 8b 45 f8 8b 48 54}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

