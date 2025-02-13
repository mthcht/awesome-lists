rule TrojanDownloader_Win32_Busky_A_2147804020_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Busky.A"
        threat_id = "2147804020"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Busky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {42 00 43 00 75 73 65 72 33 32 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_2 = {42 00 43 00 6b 65 72 6e 65 6c 33 32 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_3 = "ComSpec" wide //weight: 1
        $x_1_4 = "GetEnvironmentVariableA" ascii //weight: 1
        $x_1_5 = {81 ec 84 00 00 00 68 ?? ?? 40 00 68 ?? ?? 40 00 c3}  //weight: 1, accuracy: Low
        $x_1_6 = {3b 4d 10 0f [0-8] 8b 55 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

