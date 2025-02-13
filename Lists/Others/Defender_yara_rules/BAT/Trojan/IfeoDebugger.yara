rule Trojan_BAT_IfeoDebugger_SA_2147907153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:BAT/IfeoDebugger.SA"
        threat_id = "2147907153"
        type = "Trojan"
        platform = "BAT: Basic scripts"
        family = "IfeoDebugger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\currentversion\\image file execution options\\compattelrunner.exe" wide //weight: 1
        $x_1_2 = "/v \"debugger\" /t reg_sz /d \"%windir%\\system32\\taskkill.exe\" /f" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

