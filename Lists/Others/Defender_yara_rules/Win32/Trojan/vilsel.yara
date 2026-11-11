rule Trojan_Win32_vilsel_EM_2147981853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/vilsel.EM!MTB"
        threat_id = "2147981853"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "vilsel"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {73 74 75 6e f1 fc 24 25 31 32 56 34 34 29 15 7a 7a 7a 7a 7a 7a 7a 7a 7a}  //weight: 10, accuracy: High
        $x_10_2 = {4d 65 74 68 43 61 59 b6 df fe 6c 6c 45 6e 67 69 6e 15 ff 51 02 ff 52 02 53 56}  //weight: 10, accuracy: High
        $x_1_3 = "music.exe" ascii //weight: 1
        $x_1_4 = "musicvn.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

