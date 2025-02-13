rule HackTool_Win64_EasyKatz_2147748669_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/EasyKatz"
        threat_id = "2147748669"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "EasyKatz"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 1f 40 00 0f 1f 84 00 00 00 00 00 48 8d 54 24 7c 49 8b c6 0f 1f 84 00 00 00 00 00 0f b7 0c 42 66 3b 0c 47 75 1d 0f b7 4c 42 02 66 3b 4c 47 02 75 11 48 83 c0 02 48 83 f8 0a 75 e0 44 8b 44 24 58 eb 1e 48 8d 54 24 50 48 8b cb ff 15 ?? ?? ?? ?? 85 c0 75 b7 48 8b cb ff 15 ?? ?? ?? ?? 45 8b c6 33 d2 b9 10 04 00 00 ff 15 ?? ?? ?? ?? 48 8b f0 48 83 f8 ff 75 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "[*] lsass.exe found at %p" ascii //weight: 1
        $x_1_3 = "[*] wdigest.dll found at %p" ascii //weight: 1
        $x_1_4 = "[*] lsasrv.dll found at %p" ascii //weight: 1
        $x_1_5 = "[*] Loaded lsasrv.dll at address %p" ascii //weight: 1
        $x_1_6 = "[*] Credentials incoming" ascii //weight: 1
        $x_1_7 = "[*] Authentication Id : %d ; %d (%08x:%08x)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

