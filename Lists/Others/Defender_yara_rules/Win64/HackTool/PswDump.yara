rule HackTool_Win64_PswDump_AMTB_2147960594_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/PswDump!AMTB"
        threat_id = "2147960594"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "PswDump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Webhook URL do Discord (opcional - usado como fallback se API" ascii //weight: 2
        $x_2_2 = "o do Mirai System" ascii //weight: 2
        $x_2_3 = "/api/webhook/tunnel" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

