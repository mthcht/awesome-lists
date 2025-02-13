rule Trojan_Win32_RZStreet_2147811719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RZStreet.gen!dha"
        threat_id = "2147811719"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RZStreet"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f be 14 10 33 ca 8b 85 ?? ?? ?? ?? 03 85 ?? ?? ?? ?? 88 08}  //weight: 5, accuracy: Low
        $x_5_2 = {10 ff 75 f8 ff 35 ?? ?? ?? ?? c3 6a ?? ff 15}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

