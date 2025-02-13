rule TrojanDownloader_Win32_Seponan_A_2147930180_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Seponan.A"
        threat_id = "2147930180"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Seponan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Invoke-Expression -Command $bigScript" wide //weight: 1
        $x_1_2 = "$bigScript = Get-Content -Path" wide //weight: 1
        $x_1_3 = {6f 00 70 00 65 00 6e 00 ?? ?? ?? ?? 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "\\scripts.txt" wide //weight: 1
        $x_2_5 = {b9 35 00 00 00 be ?? ?? ?? ?? f3 a5 8d 88 d4 00 00 00 8d 04 12 50 ff 75 ?? 51 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

