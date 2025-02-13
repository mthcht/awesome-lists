rule VirTool_MSIL_Dropgent_2147748545_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Dropgent!MTB"
        threat_id = "2147748545"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dropgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "',\"127.0.0.1\");$obj = [System.Activator]::Crea" wide //weight: 1
        $x_1_2 = "ZEdWSmJuTjBZVzVqWlNna1kyOXRLVHNrYVhSbGJTQTlJQ1J2WW1vPQ==" wide //weight: 1
        $x_1_3 = ".item();$item.Document.Application.ShellExecute(\"" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

