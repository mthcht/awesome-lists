rule Trojan_Win64_Loader_EC_2147903537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Loader.EC!MTB"
        threat_id = "2147903537"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Loader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {41 8b cc 8a 45 c0 30 44 0d c1 48 ff c1 48 83 f9 14 72 f0 44 88 65 d5 0f 57 c0}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Loader_P_2147966121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Loader.P!MTB"
        threat_id = "2147966121"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Loader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[-] Failed to open payload DLL at path:" ascii //weight: 1
        $x_1_2 = "[*] Step 1: Opening sacrificial system DLL (windows.storage.dll) via NtOpenFile..." ascii //weight: 1
        $x_1_3 = "[*] Step 2: Reading payload DLL from disk..." ascii //weight: 1
        $x_1_4 = "[*] Monitoring payload execution status..." ascii //weight: 1
        $x_1_5 = "[+] Injection sequence completed successfully." ascii //weight: 1
        $x_1_6 = "[+] Contact: Stealth Loader started." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Loader_PA_2147966213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Loader.PA!MTB"
        threat_id = "2147966213"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Loader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "drop_and_execute: calling UacBypass" ascii //weight: 1
        $x_1_2 = "payload_main: persistence=%d, result=%d" ascii //weight: 1
        $x_1_3 = "payload_main: drop_and_execute returned %" ascii //weight: 1
        $x_1_4 = "payload_main: decrypting payload (hex len=%" ascii //weight: 1
        $x_1_5 = "payload_main: anti_vm passed (enabled=%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Loader_AHB_2147966285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Loader.AHB!MTB"
        threat_id = "2147966285"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Loader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {0f b6 cb 0f be c3 80 e1 ?? 41 b9 ?? ?? ?? ?? c0 e1 ?? 41 d3 e9 44 32 4c 1c 40 6b c8 ?? 44 32 c9 49 3b d0 73}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

