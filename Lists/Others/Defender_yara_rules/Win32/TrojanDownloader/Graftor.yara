rule TrojanDownloader_Win32_Graftor_SIBD_2147815523_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Graftor.SIBD!MTB"
        threat_id = "2147815523"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Graftor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "FastDownloader.exe" wide //weight: 1
        $x_1_2 = {33 d2 89 85 ?? ?? ?? ?? 66 a1 ?? ?? ?? ?? 66 89 85 ?? ?? ?? ?? a0 ?? ?? ?? ?? 88 85 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? [0-10] b8 ?? ?? ?? ?? f7 ea c1 fa ?? 8b c2 c1 e8 ?? 03 c2 8b 95 05 0f be c0 8a ca 6b c0 ?? 2a c8 80 c1 ?? 30 8c 15 00 42 89 95 05 83 fa ?? 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

