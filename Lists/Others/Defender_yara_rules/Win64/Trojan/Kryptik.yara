rule Trojan_Win64_Kryptik_MB_2147807759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kryptik.MB!MTB"
        threat_id = "2147807759"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\windows\\system32\\host.exe" ascii //weight: 1
        $x_1_2 = "/c del /q %s" ascii //weight: 1
        $x_1_3 = "Widget" wide //weight: 1
        $x_1_4 = "accKeyboardShortcut" wide //weight: 1
        $x_1_5 = "RestrictRun" ascii //weight: 1
        $x_1_6 = "Toggle StatusBar" wide //weight: 1
        $x_1_7 = "E&xit" wide //weight: 1
        $x_1_8 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_9 = "WriteFile" ascii //weight: 1
        $x_1_10 = "GetKeyState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Kryptik_PGK_2147938072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kryptik.PGK!MTB"
        threat_id = "2147938072"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {1f 0a 08 32 35 1f 0a 08 30 05 38 62 05 00 00 1e 08 32 0e 1e 08 30 05 38 f2 04 00 00 38 86 03 00 00 1f 09 08 32 0f 1f 09 08 30 05 38 09 05 00 00 38 72 03 00 00 38 6d 03 00 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Kryptik_K_2147968841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kryptik.K!AMTB"
        threat_id = "2147968841"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kryptik"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 0f b6 04 30 49 89 f9 48 c1 ff 3f 48 89 c1 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 89 d3 49 f7 e9 4c 01 ca 48 c1 fa 06 48 29 fa 48 6b d2 61 4c 89 cf 49 29 d1 45 31 c1 48 89 ca 48 c1 e1 05 48 29 d1 44 31 c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

