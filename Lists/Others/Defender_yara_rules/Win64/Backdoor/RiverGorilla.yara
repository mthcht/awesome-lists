rule Backdoor_Win64_RiverGorilla_D_2147960800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RiverGorilla.D!dha"
        threat_id = "2147960800"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RiverGorilla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"obfuscated\":true},\"_obfuscated\":true,\"capabilities\":" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_RiverGorilla_E_2147960802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RiverGorilla.E!dha"
        threat_id = "2147960802"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RiverGorilla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"obfuscated\":false},\"_obfuscated\":false,\"capabilities\":" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_RiverGorilla_F_2147960804_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RiverGorilla.F!dha"
        threat_id = "2147960804"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RiverGorilla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"obfuscated\":true},\"_obfuscated\":false,\"capabilities\":" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_RiverGorilla_G_2147960806_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/RiverGorilla.G!dha"
        threat_id = "2147960806"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "RiverGorilla"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"obfuscated\":false},\"_obfuscated\":true,\"capabilities\":" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

