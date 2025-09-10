rule Trojan_Win32_Promptlock_A_2147951896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Promptlock.A"
        threat_id = "2147951896"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Promptlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Generate clean, working Lua cod" ascii //weight: 1
        $x_1_2 = "You are a Lua code validator" ascii //weight: 1
        $x_1_3 = "/ollama/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

