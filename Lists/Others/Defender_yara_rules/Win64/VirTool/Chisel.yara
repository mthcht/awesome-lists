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
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".generatePidFile" ascii //weight: 1
        $x_1_2 = "CHISEL_KEY" ascii //weight: 1
        $x_1_3 = "chisel.pid" ascii //weight: 1
        $x_1_4 = "client.func1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

