rule Trojan_Win32_SpyKeylogger_SE_2147851243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyKeylogger.SE!MTB"
        threat_id = "2147851243"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 01 41 84 c0 75 f9}  //weight: 1, accuracy: High
        $x_1_2 = "keylogger.log" ascii //weight: 1
        $x_1_3 = "Logging output to" ascii //weight: 1
        $x_1_4 = "CallNextHookEx" ascii //weight: 1
        $x_1_5 = "GetWindowTextA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyKeylogger_GPB_2147891582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyKeylogger.GPB!MTB"
        threat_id = "2147891582"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ID\\{" wide //weight: 2
        $x_2_2 = {08 1a 74 25 e8 42 c3 89 4b b8 48 24 2a 79 40 97 72 e1 2f 7c 0c 90 0e c8 c6 8f 06 b0 b6 74 5f aa ec f3 d7 b1 70 13 5f 81 8a 05 96 80 57 f4 20 4f e5 53 3f 49 dd 03 2f be 63 03 17 58 92 98 95 63}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_SpyKeylogger_DE_2147901574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyKeylogger.DE!MTB"
        threat_id = "2147901574"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mountvol Z: /d" ascii //weight: 1
        $x_1_2 = "copy BOOTX64.efi Z:\\EFI\\Boot\\BOOTX64.efi" ascii //weight: 1
        $x_1_3 = "copy BOOTX64.efi Z:\\EFI\\Microsoft\\Boot\\bootmgfw.efi" ascii //weight: 1
        $x_1_4 = "CustomMSGBox.exe" ascii //weight: 1
        $x_1_5 = "BananaAntimatterTrojan.pdb" ascii //weight: 1
        $x_1_6 = "Task Manager" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

