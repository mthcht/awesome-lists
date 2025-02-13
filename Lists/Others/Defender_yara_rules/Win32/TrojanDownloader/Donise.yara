rule TrojanDownloader_Win32_Donise_A_2147611126_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Donise.A"
        threat_id = "2147611126"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Donise"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {53 53 50 ff 75 ?? 53 e8 ?? ?? ?? ?? 85 c0 75 50 8d 85 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 8b f0 59 3b f3 59 74 36 56 6a 01 8d 45 ?? 6a 02 50 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 83 c4 14 66 81 7d fe 5a 4d 74 1c 66 81 7d fe 4d 5a 74 14 8d 85 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 33 c0 5f 5e 5b c9 c3 8d 45 a4 50 8d 45 b4 50 53 53 53 53 53 8d 85 ?? ?? ?? ?? 53 50 53 ff 15}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

