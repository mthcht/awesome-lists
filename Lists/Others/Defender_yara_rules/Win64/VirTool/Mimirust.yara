rule VirTool_Win64_Mimirust_A_2147814921_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Mimirust.A!MTB"
        threat_id = "2147814921"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Mimirust"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mimiRust" ascii //weight: 1
        $x_1_2 = "lsass.exe" ascii //weight: 1
        $x_1_3 = "dump-credentials" ascii //weight: 1
        $x_1_4 = "dump-hashes" ascii //weight: 1
        $x_1_5 = "wdigest\\mod.rs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

