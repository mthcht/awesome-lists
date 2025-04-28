rule VirTool_Win64_Chisel_G_2147929112_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Chisel.G"
        threat_id = "2147929112"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Chisel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "jpillora/chisel" ascii //weight: 5
        $x_5_2 = "CHISEL_KEY" ascii //weight: 5
        $x_5_3 = "chisel.pid" ascii //weight: 5
        $x_1_4 = "client.func1" ascii //weight: 1
        $x_1_5 = ".GenerateKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

