rule Trojan_Win32_BunnyLoader_RPX_2147892948_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunnyLoader.RPX!MTB"
        threat_id = "2147892948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunnyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BunnyLoader_" ascii //weight: 1
        $x_1_2 = "BotID=" ascii //weight: 1
        $x_1_3 = "Bunny/TaskHandler.php" ascii //weight: 1
        $x_1_4 = "Run Stealer" ascii //weight: 1
        $x_1_5 = "Echoer.php" ascii //weight: 1
        $x_1_6 = "notepad.exe" ascii //weight: 1
        $x_1_7 = "John Doe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunnyLoader_RPX_2147892948_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunnyLoader.RPX!MTB"
        threat_id = "2147892948"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunnyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ollydbg.exe" wide //weight: 1
        $x_1_2 = "BunnyLoader" wide //weight: 1
        $x_1_3 = "BL2.0" wide //weight: 1
        $x_1_4 = "maltest" wide //weight: 1
        $x_1_5 = "russianpanda" ascii //weight: 1
        $x_1_6 = "cod3nym" ascii //weight: 1
        $x_1_7 = "honey@pot.com.pst" ascii //weight: 1
        $x_1_8 = "notepad.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_BunnyLoader_GDR_2147905572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/BunnyLoader.GDR!MTB"
        threat_id = "2147905572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "BunnyLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 01 88 04 37 8b c6 88 11 8d 75 ed 0f b6 04 07 03 45 ac 0f b6 c0 0f b6 0c 38 0f be c6 33 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

