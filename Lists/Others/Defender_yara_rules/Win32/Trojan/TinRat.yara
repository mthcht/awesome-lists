rule Trojan_Win32_TinRat_A_2147735060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TinRat.A"
        threat_id = "2147735060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TinRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TiniMetI.exe" ascii //weight: 1
        $x_1_2 = "PwmSvc.exe" ascii //weight: 1
        $x_1_3 = "uiSeAgnt.exe" ascii //weight: 1
        $x_1_4 = "coreServiceShell.exe" ascii //weight: 1
        $x_1_5 = "PtSessionAgent.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_Win32_TinRat_B_2147735063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TinRat.B"
        threat_id = "2147735063"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TinRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 01 00 00 00 8b 1d 58 81 40 00 03 1d 6c 81 40 00 53 68 ?? ?? ?? ?? e8 96 00 00 00 68 01 00 00 00 a1 60 81 40 00 89 c3 03 1d 68 81 40 00 53 68 ?? ?? ?? ?? e8 79 00 00 00 8b 1d ?? ?? ?? ?? 33 1d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 68 01 00 00 00 68 ?? ?? ?? ?? 8b 1d 58 81 40 00 03 1d 6c 81 40 00 53 e8 4b 00 00 00 ff 05 68 81 40 00 8b 1d 68 81 40 00 3b 1d 64 81 40 00 7e 0a c7 05 68 81 40 00 00 00 00 00 83 05 6c 81 40 00 03 e9 5d ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

