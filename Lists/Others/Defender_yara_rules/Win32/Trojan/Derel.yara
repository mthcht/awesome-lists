rule Trojan_Win32_Derel_A_2147679814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Derel.A"
        threat_id = "2147679814"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Derel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "/harmonyzz/pages/fulljustunhook.php" wide //weight: 10
        $x_10_2 = "/harmonyzz/api.php" wide //weight: 10
        $x_1_3 = "Wow64DisableWow64FsRedirection" ascii //weight: 1
        $x_1_4 = "stop VSS" ascii //weight: 1
        $x_1_5 = "delete shadows /all /quiet" wide //weight: 1
        $x_3_6 = {c7 05 00 62 40 00 01 00 00 00 66 8b ?? ?? ?? 40 00 66 89 ?? c0 8d ?? c0}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

