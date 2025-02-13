rule Trojan_Win32_Barkiofork_A_2147649799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barkiofork.A"
        threat_id = "2147649799"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barkiofork"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 3d 31 00 2f 73 2f 61 73 70 3f}  //weight: 1, accuracy: High
        $x_1_2 = {61 76 70 2e 65 78 65 00 5c 63 6d 64 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {25 75 20 4d 42 28 25 73 29 2f 25 75 20 4d 42 28 25 73 29 0a}  //weight: 1, accuracy: High
        $x_1_4 = "%USERPROFILE%\\Temp\\~ISUN32.EXE" ascii //weight: 1
        $x_1_5 = {75 11 b9 bb 01 00 00 eb 0a 8b 4d 0c 3b cf 75 03 6a 50}  //weight: 1, accuracy: High
        $x_3_6 = {77 1b 8b c1 0f af c1 0f af c1 25 ff 00 00 00 3d 80 00 00 00 76 07 30 ?? ?? ?? ?? ?? ?? 41}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Barkiofork_B_2147654172_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barkiofork.B"
        threat_id = "2147654172"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barkiofork"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "(%d) %.64s\\%.64s|%.64s|%.64s|%.64s" ascii //weight: 1
        $x_1_2 = "<**CFG**>Startup" ascii //weight: 1
        $x_1_3 = "B:Use .ini file=1" ascii //weight: 1
        $x_1_4 = "Enable Logging" ascii //weight: 1
        $x_1_5 = "Logging File Name" ascii //weight: 1
        $x_1_6 = "Plugin_%d" ascii //weight: 1
        $x_1_7 = "S[16]:Language=English" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Barkiofork_C_2147690179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barkiofork.C!dha"
        threat_id = "2147690179"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barkiofork"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hgcurtain.com" ascii //weight: 1
        $x_1_2 = "&p=1&e=2&seed=" ascii //weight: 1
        $x_1_3 = "/s/asp?tr=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Barkiofork_2147695070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Barkiofork!dha"
        threat_id = "2147695070"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Barkiofork"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%USERPROFILE%\\Temp\\~ISUN32.EXE" ascii //weight: 1
        $x_1_2 = "/2011/n325423.shtml?" ascii //weight: 1
        $x_1_3 = "MAC Address: %02X-%02X-%02X-%02X-%02X-%02X" ascii //weight: 1
        $x_1_4 = "Drive Serial Number_______________: [%s]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

