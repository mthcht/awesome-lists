rule HackTool_Win64_PWDump_M_2147744665_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PWDump.M!MSR"
        threat_id = "2147744665"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PWDump"
        severity = "High"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pwsrv.exe" ascii //weight: 1
        $x_1_2 = "starting dll injection" ascii //weight: 1
        $x_1_3 = "createremotethread ok" ascii //weight: 1
        $x_1_4 = "servpw64.exe" ascii //weight: 1
        $x_1_5 = "lsaext.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule HackTool_Win64_PWDump_PTC_2147949002_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PWDump.PTC!MTB"
        threat_id = "2147949002"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PWDump"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {4c 2b e6 4c 89 74 24 ?? 4d 8b cc 4c 8b c6 48 8b d7 4c 8b 74 24 ?? 49 8b ce ff 15}  //weight: 4, accuracy: Low
        $x_2_2 = {4c 89 64 24 ?? 44 89 64 24 ?? 4c 89 64 24 ?? 4c 8b cb 45 33 c0 33 d2 49 8b ce ff 15}  //weight: 2, accuracy: Low
        $x_2_3 = "Chrome App-Bound Encryption Decryption" ascii //weight: 2
        $x_2_4 = "Cookies / Passwords / Payment Methods" ascii //weight: 2
        $x_2_5 = "Reflective DLL Process Injection" ascii //weight: 2
        $x_2_6 = "chrome_decrypt.dll" ascii //weight: 2
        $x_1_7 = "Terminating browser PID" ascii //weight: 1
        $x_1_8 = "chrome_decrypt.log" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

