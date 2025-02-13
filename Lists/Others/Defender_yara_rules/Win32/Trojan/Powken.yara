rule Trojan_Win32_Powken_R_2147899224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Powken.R!MTB"
        threat_id = "2147899224"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Powken"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "poweroff.exe" wide //weight: 1
        $x_1_2 = "verysilent" wide //weight: 1
        $x_1_3 = "connectini.net/S2S/Disc/Disc.php" wide //weight: 1
        $x_1_4 = "Sandboxie" wide //weight: 1
        $x_1_5 = "Intel" wide //weight: 1
        $x_1_6 = "DrWeb" wide //weight: 1
        $x_1_7 = "ESET" wide //weight: 1
        $x_1_8 = "AVAST" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

