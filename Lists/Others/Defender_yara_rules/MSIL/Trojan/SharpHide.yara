rule Trojan_MSIL_SharpHide_PA_2147930814_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SharpHide.PA!MTB"
        threat_id = "2147930814"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SharpHide"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SharpHide.pdb" ascii //weight: 1
        $x_1_2 = "mshta vbscript:close(CreateObject(\"WScript.Shell\").Run(\"powershell" wide //weight: 1
        $x_2_3 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 [0-32] 61 00 64 00 53 00 74 00 72 00 69 00 6e 00 67 00 28 00 27 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-8] 2e 00 [0-8] 2e 00 [0-8] 2e 00 [0-8] 2f 00 [0-16] 2f 00 [0-16] 2e 00 70 00 6e 00 67 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

