rule Trojan_Win32_Tavdig_Crypt_2147914813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Tavdig.Crypt!dha"
        threat_id = "2147914813"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Tavdig"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "400"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "ExecutePatch" ascii //weight: 100
        $x_100_2 = "Main@12" ascii //weight: 100
        $x_100_3 = "MakeUuid" ascii //weight: 100
        $x_100_4 = "kAiCode" ascii //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

