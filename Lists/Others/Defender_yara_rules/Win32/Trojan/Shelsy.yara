rule Trojan_Win32_Shelsy_B_2147827450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Shelsy.B!MTB"
        threat_id = "2147827450"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Shelsy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Legpuller.exe" wide //weight: 1
        $x_1_2 = "cochairing.ini" wide //weight: 1
        $x_1_3 = "unskelighedens.ini" wide //weight: 1
        $x_1_4 = "Desertrer133" wide //weight: 1
        $x_1_5 = "Reklamemagers125.exe" wide //weight: 1
        $x_1_6 = "C:\\TEMP\\Gaardmand.qui" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

