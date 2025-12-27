rule HackTool_JS_HeldPony_C_2147955101_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:JS/HeldPony.C"
        threat_id = "2147955101"
        type = "HackTool"
        platform = "JS: JavaScript scripts"
        family = "HeldPony"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Users\\Public\\Controller\\btdlg.js" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

