rule Trojan_Win32_Galileo_A_2147723910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Galileo.A!!Galileo.gen!A"
        threat_id = "2147723910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Galileo"
        severity = "Critical"
        info = "Galileo: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DXGI WARNING: Live Producet at" ascii //weight: 10
        $x_10_2 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 4c 00 69 00 73 00 74 00 20 00 28 00 78 00 38 00 36 00 29 00 3a 00 0a 00 25 00 73 00}  //weight: 10, accuracy: High
        $x_10_3 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 4c 00 69 00 73 00 74 00 20 00 28 00 78 00 36 00 34 00 29 00 3a 00 0a 00 25 00 73 00}  //weight: 10, accuracy: High
        $x_10_4 = "RAM: %dMB free %dMB total (%u%% used)" wide //weight: 10
        $x_10_5 = "Registered to: %s%s%s%s {%s}" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

