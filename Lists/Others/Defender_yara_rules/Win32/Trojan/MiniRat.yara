rule Trojan_Win32_MiniRat_DB_2147968324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MiniRat.DB!MTB"
        threat_id = "2147968324"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MiniRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Projects\\ali\\proj\\Mini rat\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

