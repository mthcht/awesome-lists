rule PUA_MSIL_RnsmSim_J_259986_0
{
    meta:
        author = "defender2yara"
        detection_name = "PUA:MSIL/RnsmSim.J!ibt"
        threat_id = "259986"
        type = "PUA"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RnsmSim"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Starter.exe" ascii //weight: 1
        $x_1_2 = "ObfuscatedByAgileDotNetAttribute" ascii //weight: 1
        $x_1_3 = "2473fbde-0c24-41a0-bb03-4ffbd69e78c6" ascii //weight: 1
        $x_1_4 = "WindowsImpersonationContext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

