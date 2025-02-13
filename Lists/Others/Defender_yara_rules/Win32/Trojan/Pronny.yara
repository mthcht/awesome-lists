rule Trojan_Win32_Pronny_RH_2147842692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pronny.RH!MTB"
        threat_id = "2147842692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pronny"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {6f 6c 31 00 6e 6b 2e d5 00 8b 85 52 a7 b4 45 99 0b 66 ab 2c 99 24 41}  //weight: 5, accuracy: High
        $x_1_2 = "Homiliary Unbriefly lindon" wide //weight: 1
        $x_1_3 = "sensationistic" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

