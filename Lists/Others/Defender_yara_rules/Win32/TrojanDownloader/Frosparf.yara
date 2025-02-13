rule TrojanDownloader_Win32_Frosparf_A_2147706103_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Frosparf.A"
        threat_id = "2147706103"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Frosparf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "/cdn.pekalongan-kummunity.com" wide //weight: 2
        $x_2_2 = {49 00 6e 00 6a 00 65 00 63 00 74 00 4d 00 4e 00 [0-6] 5c 00 70 00 65 00 6b 00 61 00 6c 00 6f 00 6e 00 67 00 61 00 6e 00 2e 00 76 00 62 00 70 00}  //weight: 2, accuracy: Low
        $x_1_3 = "/files/zza15.zip" wide //weight: 1
        $x_1_4 = "windows\\073CZ59.exe" wide //weight: 1
        $x_1_5 = "HackAlert" ascii //weight: 1
        $x_1_6 = "Credit Cheat Pekalongan Kommuniti" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

